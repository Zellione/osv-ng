//! Bounded image probing, derived-image generation, caches, and viewer state.
//! Parsing and decoding consume bytes only: callers stream already-authenticated
//! object chunks and never grant a decoder vault paths or key authority.

use image::{AnimationDecoder, ImageDecoder, ImageEncoder, ImageReader, codecs::png::PngEncoder};
use osv_crypto::SecretBytes;
use std::{collections::VecDeque, error::Error, fmt, path::Path};
use zeroize::Zeroize;

pub const THUMBNAIL_RECIPE_VERSION: u32 = 1;
pub const MAX_ENCODED_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_DIMENSION: u32 = 65_535;
pub const MAX_PIXELS: u64 = 100_000_000;
pub const MAX_ANIMATION_PIXEL_FRAMES: u64 = 200_000_000;
pub const MAX_ANIMATION_FRAMES: u32 = 1_000;
pub const MAX_THUMBNAIL_RESULT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_VIEWER_RESULT_BYTES: usize = 96 * 1024 * 1024;
pub const WORKER_RESULT_HEADER_LEN: usize = 64;
pub const WORKER_REQUEST_HEADER_LEN: usize = 16;
pub const THUMBNAIL_EDGE: u32 = 512;
pub const MAX_VIEWER_EDGE: u32 = 4096;
const MAX_DECODER_ALLOC: u64 = 400 * 1024 * 1024;

fn decoder_limits() -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(MAX_DECODER_ALLOC);
    limits
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ImagePurpose {
    Thumbnail = 1,
    Viewer = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Gif,
    Webp,
}
impl ImageFormat {
    #[must_use]
    pub const fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Orientation {
    Normal,
    MirrorHorizontal,
    Rotate180,
    MirrorVertical,
    MirrorHorizontalRotate270,
    Rotate90,
    MirrorHorizontalRotate90,
    Rotate270,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageProbe {
    pub format: ImageFormat,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub orientation: Orientation,
    pub has_color_profile: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerImageResult {
    pub source: ImageProbe,
    pub thumbnail_width: u32,
    pub thumbnail_height: u32,
    pub thumbnail_png_len: u32,
    pub rgba_len: u32,
    pub purpose: ImagePurpose,
    pub requested_edge: u32,
    pub output_frames: u32,
    pub first_delay_ms: u32,
    pub additional_frames_len: u32,
}

pub fn encode_worker_request(purpose: ImagePurpose, edge: u32) -> Result<[u8; 16], ImageError> {
    if (purpose == ImagePurpose::Thumbnail && edge != THUMBNAIL_EDGE)
        || (purpose == ImagePurpose::Viewer && !(THUMBNAIL_EDGE..=MAX_VIEWER_EDGE).contains(&edge))
    {
        return Err(ImageError::ResourceLimit);
    }
    let mut header = [0; WORKER_REQUEST_HEADER_LEN];
    header[..8].copy_from_slice(b"OSVREQ1\0");
    header[8] = purpose as u8;
    header[12..16].copy_from_slice(&edge.to_le_bytes());
    Ok(header)
}

pub fn image_worker_result_from_request(request: &[u8]) -> Result<SecretBytes, ImageError> {
    if request.len() <= WORKER_REQUEST_HEADER_LEN
        || &request[..8] != b"OSVREQ1\0"
        || request[9..12] != [0; 3]
    {
        return Err(ImageError::Malformed);
    }
    let purpose = match request[8] {
        1 => ImagePurpose::Thumbnail,
        2 => ImagePurpose::Viewer,
        _ => return Err(ImageError::Malformed),
    };
    let edge = u32::from_le_bytes(
        request[12..16]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    encode_worker_request(purpose, edge)?;
    image_worker_result_for(&request[WORKER_REQUEST_HEADER_LEN..], purpose, edge)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageError {
    Unsupported,
    Malformed,
    ResourceLimit,
    Decode,
}

pub struct DecodedAnimationFrame {
    pub pixels: SecretBytes,
    pub width: u32,
    pub height: u32,
    pub delay_ms: u32,
}

struct WipeRgba(image::RgbaImage);

impl WipeRgba {
    fn wipe(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl Drop for WipeRgba {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for DecodedAnimationFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecodedAnimationFrame([REDACTED])")
    }
}

pub fn animation_frames(bytes: &[u8], edge: u32) -> Result<Vec<DecodedAnimationFrame>, ImageError> {
    let info = probe(bytes)?;
    if info.frames <= 1 || !(THUMBNAIL_EDGE..=MAX_VIEWER_EDGE).contains(&edge) {
        return Err(ImageError::Unsupported);
    }
    let cursor = std::io::Cursor::new(bytes);
    let frames = match info.format {
        ImageFormat::Gif => {
            let mut decoder = image::codecs::gif::GifDecoder::new(std::io::BufReader::new(cursor))
                .map_err(|_| ImageError::Decode)?;
            decoder
                .set_limits(decoder_limits())
                .map_err(|_| ImageError::ResourceLimit)?;
            decoder.into_frames().collect_frames()
        }
        ImageFormat::Webp => {
            let mut decoder =
                image::codecs::webp::WebPDecoder::new(std::io::BufReader::new(cursor))
                    .map_err(|_| ImageError::Decode)?;
            decoder
                .set_limits(decoder_limits())
                .map_err(|_| ImageError::ResourceLimit)?;
            decoder.into_frames().collect_frames()
        }
        ImageFormat::Png => {
            let decoder = image::codecs::png::PngDecoder::with_limits(
                std::io::BufReader::new(cursor),
                decoder_limits(),
            )
            .map_err(|_| ImageError::Decode)?;
            if !decoder.is_apng().map_err(|_| ImageError::Decode)? {
                return Err(ImageError::Unsupported);
            }
            decoder
                .apng()
                .map_err(|_| ImageError::Decode)?
                .into_frames()
                .collect_frames()
        }
        ImageFormat::Jpeg => return Err(ImageError::Unsupported),
    }
    .map_err(|_| ImageError::Decode)?;
    if frames.len() != info.frames as usize || frames.len() > MAX_ANIMATION_FRAMES as usize {
        return Err(ImageError::Malformed);
    }
    let mut protected = Vec::with_capacity(frames.len());
    let mut total = 0usize;
    for frame in frames {
        if frame.left() != 0
            || frame.top() != 0
            || frame.buffer().width() != info.width
            || frame.buffer().height() != info.height
        {
            return Err(ImageError::Malformed);
        }
        let (numerator, denominator) = frame.delay().numer_denom_ms();
        if denominator == 0 {
            return Err(ImageError::Malformed);
        }
        let delay_ms = numerator
            .checked_add(denominator - 1)
            .ok_or(ImageError::ResourceLimit)?
            / denominator;
        let delay_ms = delay_ms.max(10);
        if delay_ms > 60_000 {
            return Err(ImageError::ResourceLimit);
        }
        let buffer = frame.into_buffer();
        let scaled = if buffer.width() > edge || buffer.height() > edge {
            image::DynamicImage::ImageRgba8(buffer)
                .thumbnail(edge, edge)
                .to_rgba8()
        } else {
            buffer
        };
        let width = scaled.width();
        let height = scaled.height();
        let mut raw = scaled.into_raw();
        total = total
            .checked_add(raw.len())
            .filter(|total| *total <= MAX_VIEWER_RESULT_BYTES)
            .ok_or(ImageError::ResourceLimit)?;
        let pixels = SecretBytes::new(&raw).map_err(|_| ImageError::Decode)?;
        raw.zeroize();
        protected.push(DecodedAnimationFrame {
            pixels,
            width,
            height,
            delay_ms,
        });
    }
    Ok(protected)
}
impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("image input was rejected safely")
    }
}
impl Error for ImageError {}

/// Probes allowlisted metadata without decoder allocation, then applies limits.
pub fn probe(bytes: &[u8]) -> Result<ImageProbe, ImageError> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(ImageError::ResourceLimit);
    }
    let info = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        probe_png(bytes)
    } else if bytes.starts_with(b"\xff\xd8") {
        probe_jpeg(bytes)
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        probe_gif(bytes)
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        probe_webp(bytes)
    } else {
        Err(ImageError::Unsupported)
    }?;
    let pixels = u64::from(info.width)
        .checked_mul(u64::from(info.height))
        .ok_or(ImageError::ResourceLimit)?;
    if info.width == 0
        || info.height == 0
        || info.width > MAX_DIMENSION
        || info.height > MAX_DIMENSION
        || pixels > MAX_PIXELS
        || pixels
            .checked_mul(u64::from(info.frames))
            .is_none_or(|total| total > MAX_ANIMATION_PIXEL_FRAMES)
        || info.frames == 0
        || info.frames > MAX_ANIMATION_FRAMES
    {
        Err(ImageError::ResourceLimit)
    } else {
        Ok(info)
    }
}
fn probe_png(b: &[u8]) -> Result<ImageProbe, ImageError> {
    if b.len() < 33 || &b[8..12] != 13u32.to_be_bytes().as_slice() || &b[12..16] != b"IHDR" {
        return Err(ImageError::Malformed);
    }
    let width = u32::from_be_bytes(b[16..20].try_into().map_err(|_| ImageError::Malformed)?);
    let height = u32::from_be_bytes(b[20..24].try_into().map_err(|_| ImageError::Malformed)?);
    let mut p = 8usize;
    let mut frames = 1;
    let mut profile = false;
    let mut saw_idat = false;
    let mut saw_iend = false;
    let mut saw_animation_control = false;
    let mut animation_frame_controls = 0u32;
    let mut expected_animation_sequence = 0u32;
    let mut saw_frame_control = false;
    while p.checked_add(12).is_some_and(|x| x <= b.len()) {
        let n =
            u32::from_be_bytes(b[p..p + 4].try_into().map_err(|_| ImageError::Malformed)?) as usize;
        let end = p
            .checked_add(12)
            .and_then(|x| x.checked_add(n))
            .filter(|x| *x <= b.len())
            .ok_or(ImageError::Malformed)?;
        let kind = &b[p + 4..p + 8];
        let expected_crc = u32::from_be_bytes(
            b[end - 4..end]
                .try_into()
                .map_err(|_| ImageError::Malformed)?,
        );
        let mut crc = crc32fast::Hasher::new();
        crc.update(kind);
        crc.update(&b[p + 8..end - 4]);
        if crc.finalize() != expected_crc {
            return Err(ImageError::Malformed);
        }
        if kind == b"acTL" {
            if n != 8 || saw_animation_control || saw_idat {
                return Err(ImageError::Malformed);
            }
            saw_animation_control = true;
            frames = u32::from_be_bytes(
                b[p + 8..p + 12]
                    .try_into()
                    .map_err(|_| ImageError::Malformed)?,
            )
        }
        if kind == b"fcTL" {
            if !saw_animation_control || n != 26 {
                return Err(ImageError::Malformed);
            }
            let data = &b[p + 8..end - 4];
            let sequence =
                u32::from_be_bytes(data[0..4].try_into().map_err(|_| ImageError::Malformed)?);
            let frame_width =
                u32::from_be_bytes(data[4..8].try_into().map_err(|_| ImageError::Malformed)?);
            let frame_height =
                u32::from_be_bytes(data[8..12].try_into().map_err(|_| ImageError::Malformed)?);
            let x = u32::from_be_bytes(data[12..16].try_into().map_err(|_| ImageError::Malformed)?);
            let y = u32::from_be_bytes(data[16..20].try_into().map_err(|_| ImageError::Malformed)?);
            if sequence != expected_animation_sequence
                || frame_width == 0
                || frame_height == 0
                || x.checked_add(frame_width).is_none_or(|end| end > width)
                || y.checked_add(frame_height).is_none_or(|end| end > height)
                || data[24] > 2
                || data[25] > 1
            {
                return Err(ImageError::Malformed);
            }
            expected_animation_sequence = expected_animation_sequence
                .checked_add(1)
                .ok_or(ImageError::ResourceLimit)?;
            animation_frame_controls = animation_frame_controls
                .checked_add(1)
                .ok_or(ImageError::ResourceLimit)?;
            saw_frame_control = true;
        }
        if kind == b"fdAT" {
            if !saw_animation_control || !saw_frame_control || n < 4 {
                return Err(ImageError::Malformed);
            }
            let sequence = u32::from_be_bytes(
                b[p + 8..p + 12]
                    .try_into()
                    .map_err(|_| ImageError::Malformed)?,
            );
            if sequence != expected_animation_sequence {
                return Err(ImageError::Malformed);
            }
            expected_animation_sequence = expected_animation_sequence
                .checked_add(1)
                .ok_or(ImageError::ResourceLimit)?;
        }
        if kind == b"IHDR" && p != 8 {
            return Err(ImageError::Malformed);
        }
        profile |= matches!(kind, b"iCCP" | b"sRGB" | b"cHRM" | b"gAMA");
        saw_idat |= kind == b"IDAT";
        p = end;
        if kind == b"IEND" {
            if n != 0 || p != b.len() {
                return Err(ImageError::Malformed);
            }
            saw_iend = true;
            break;
        }
    }
    if !saw_idat
        || !saw_iend
        || (saw_animation_control && animation_frame_controls != frames)
        || (!saw_animation_control && animation_frame_controls != 0)
    {
        return Err(ImageError::Malformed);
    }
    Ok(ImageProbe {
        format: ImageFormat::Png,
        width,
        height,
        frames,
        orientation: Orientation::Normal,
        has_color_profile: profile,
    })
}
fn probe_gif(b: &[u8]) -> Result<ImageProbe, ImageError> {
    if b.len() < 13 {
        return Err(ImageError::Malformed);
    }
    let width = u16::from_le_bytes([b[6], b[7]]) as u32;
    let height = u16::from_le_bytes([b[8], b[9]]) as u32;
    let mut frames = 0u32;
    let mut p = 13usize;
    if b[10] & 0x80 != 0 {
        p = p
            .checked_add(3 * (1usize << (usize::from(b[10] & 7) + 1)))
            .ok_or(ImageError::Malformed)?
    }
    let mut saw_trailer = false;
    while p < b.len() {
        match b[p] {
            0x2c => {
                frames = frames.checked_add(1).ok_or(ImageError::ResourceLimit)?;
                if frames > MAX_ANIMATION_FRAMES {
                    return Err(ImageError::ResourceLimit);
                }
                p = skip_gif_image(b, p, width, height)?
            }
            0x21 => {
                if p + 2 > b.len() {
                    return Err(ImageError::Malformed);
                }
                p = skip_gif_extension(b, p)?
            }
            0x3b => {
                p += 1;
                saw_trailer = true;
                break;
            }
            _ => return Err(ImageError::Malformed),
        }
    }
    if frames == 0 || !saw_trailer || p != b.len() {
        return Err(ImageError::Malformed);
    }
    Ok(ImageProbe {
        format: ImageFormat::Gif,
        width,
        height,
        frames,
        orientation: Orientation::Normal,
        has_color_profile: false,
    })
}
fn skip_gif_extension(b: &[u8], p: usize) -> Result<usize, ImageError> {
    match *b.get(p + 1).ok_or(ImageError::Malformed)? {
        0xf9 => {
            let extension = b.get(p..p + 8).ok_or(ImageError::Malformed)?;
            let packed = extension[3];
            if extension[2] != 4 || extension[7] != 0 || packed & 0xe0 != 0 || (packed >> 2) & 7 > 3
            {
                return Err(ImageError::Malformed);
            }
            Ok(p + 8)
        }
        0xfe => skip_sub_blocks(b, p + 2),
        0xff => {
            if *b.get(p + 2).ok_or(ImageError::Malformed)? != 11 {
                return Err(ImageError::Malformed);
            }
            skip_sub_blocks(b, p.checked_add(14).ok_or(ImageError::Malformed)?)
        }
        0x01 => {
            if *b.get(p + 2).ok_or(ImageError::Malformed)? != 12 {
                return Err(ImageError::Malformed);
            }
            skip_sub_blocks(b, p.checked_add(15).ok_or(ImageError::Malformed)?)
        }
        _ => Err(ImageError::Malformed),
    }
}
fn skip_gif_image(
    b: &[u8],
    p: usize,
    canvas_width: u32,
    canvas_height: u32,
) -> Result<usize, ImageError> {
    if p + 10 > b.len() {
        return Err(ImageError::Malformed);
    }
    let left = u32::from(u16::from_le_bytes([b[p + 1], b[p + 2]]));
    let top = u32::from(u16::from_le_bytes([b[p + 3], b[p + 4]]));
    let width = u32::from(u16::from_le_bytes([b[p + 5], b[p + 6]]));
    let height = u32::from(u16::from_le_bytes([b[p + 7], b[p + 8]]));
    if width == 0
        || height == 0
        || left.checked_add(width).is_none_or(|x| x > canvas_width)
        || top.checked_add(height).is_none_or(|x| x > canvas_height)
    {
        return Err(ImageError::ResourceLimit);
    }
    let packed = b[p + 9];
    let mut x = p + 10;
    if packed & 0x80 != 0 {
        x = x
            .checked_add(3 * (1usize << (usize::from(packed & 7) + 1)))
            .ok_or(ImageError::Malformed)?
    }
    if x >= b.len() {
        return Err(ImageError::Malformed);
    }
    skip_sub_blocks(b, x + 1)
}
fn skip_sub_blocks(b: &[u8], mut p: usize) -> Result<usize, ImageError> {
    loop {
        let n = usize::from(*b.get(p).ok_or(ImageError::Malformed)?);
        p += 1;
        if n == 0 {
            return Ok(p);
        }
        p = p
            .checked_add(n)
            .filter(|x| *x <= b.len())
            .ok_or(ImageError::Malformed)?
    }
}
fn probe_jpeg(b: &[u8]) -> Result<ImageProbe, ImageError> {
    let mut p = 2usize;
    let mut geometry = None;
    let mut orientation = Orientation::Normal;
    let mut profile = false;
    while p + 4 <= b.len() {
        if b[p] != 0xff {
            return Err(ImageError::Malformed);
        }
        while p < b.len() && b[p] == 0xff {
            p += 1
        }
        let marker = *b.get(p).ok_or(ImageError::Malformed)?;
        p += 1;
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        if matches!(marker, 0x01 | 0xd0..=0xd7) {
            continue;
        }
        let n = u16::from_be_bytes(
            b.get(p..p + 2)
                .ok_or(ImageError::Malformed)?
                .try_into()
                .map_err(|_| ImageError::Malformed)?,
        ) as usize;
        if n < 2 || p.checked_add(n).is_none_or(|x| x > b.len()) {
            return Err(ImageError::Malformed);
        }
        let data = &b[p + 2..p + n];
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            if data.len() < 5 {
                return Err(ImageError::Malformed);
            }
            geometry = Some((
                u16::from_be_bytes([data[3], data[4]]) as u32,
                u16::from_be_bytes([data[1], data[2]]) as u32,
            ))
        }
        if marker == 0xe1 && data.starts_with(b"Exif\0\0") {
            orientation = parse_exif_orientation(&data[6..]).unwrap_or(Orientation::Normal)
        }
        profile |= marker == 0xe2 && data.starts_with(b"ICC_PROFILE\0");
        p += n
    }
    let (width, height) = geometry.ok_or(ImageError::Malformed)?;
    Ok(ImageProbe {
        format: ImageFormat::Jpeg,
        width,
        height,
        frames: 1,
        orientation,
        has_color_profile: profile,
    })
}
fn parse_exif_orientation(t: &[u8]) -> Option<Orientation> {
    if t.len() < 8 {
        return None;
    }
    let le = match &t[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16at = |p| {
        let a: [u8; 2] = t.get(p..p + 2)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    };
    let u32at = |p| {
        let a: [u8; 4] = t.get(p..p + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    };
    if u16at(2)? != 42 {
        return None;
    }
    let base = usize::try_from(u32at(4)?).ok()?;
    for x in 0..usize::from(u16at(base)?) {
        let p = base + 2 + x * 12;
        if u16at(p)? == 0x112 && u16at(p + 2)? == 3 && u32at(p + 4)? == 1 {
            return match u16at(p + 8)? {
                1 => Some(Orientation::Normal),
                2 => Some(Orientation::MirrorHorizontal),
                3 => Some(Orientation::Rotate180),
                4 => Some(Orientation::MirrorVertical),
                5 => Some(Orientation::MirrorHorizontalRotate270),
                6 => Some(Orientation::Rotate90),
                7 => Some(Orientation::MirrorHorizontalRotate90),
                8 => Some(Orientation::Rotate270),
                _ => None,
            };
        }
    }
    None
}
fn probe_webp(b: &[u8]) -> Result<ImageProbe, ImageError> {
    if b.len() < 30 || &b[12..16] != b"VP8X" {
        return Err(ImageError::Unsupported);
    }
    let riff_len =
        u32::from_le_bytes(b[4..8].try_into().map_err(|_| ImageError::Malformed)?) as usize;
    if riff_len.checked_add(8) != Some(b.len()) || &b[16..20] != 10u32.to_le_bytes().as_slice() {
        return Err(ImageError::Malformed);
    }
    let flags = b[20];
    if flags & 0xc1 != 0 || b[21..24] != [0; 3] {
        return Err(ImageError::Malformed);
    }
    let width = 1 + u32::from_le_bytes([b[24], b[25], b[26], 0]);
    let height = 1 + u32::from_le_bytes([b[27], b[28], b[29], 0]);
    let frame_count = validate_webp_chunks(b, width, height)?;
    let frames = if flags & 2 != 0 {
        if frame_count == 0 {
            return Err(ImageError::Malformed);
        }
        frame_count
    } else {
        if frame_count != 0 {
            return Err(ImageError::Malformed);
        }
        1
    };
    Ok(ImageProbe {
        format: ImageFormat::Webp,
        width,
        height,
        frames,
        orientation: Orientation::Normal,
        has_color_profile: flags & 0x20 != 0,
    })
}
fn validate_webp_chunks(
    b: &[u8],
    canvas_width: u32,
    canvas_height: u32,
) -> Result<u32, ImageError> {
    let mut p = 12usize;
    let mut count = 0u32;
    while p + 8 <= b.len() {
        let n = u32::from_le_bytes(
            b[p + 4..p + 8]
                .try_into()
                .map_err(|_| ImageError::Malformed)?,
        ) as usize;
        let chunk_end = p
            .checked_add(8 + n + (n & 1))
            .filter(|end| *end <= b.len())
            .ok_or(ImageError::Malformed)?;
        if &b[p..p + 4] == b"ANMF" {
            if n < 16 {
                return Err(ImageError::Malformed);
            }
            let data = &b[p + 8..p + 8 + n];
            let x = 2 * u32::from_le_bytes([data[0], data[1], data[2], 0]);
            let y = 2 * u32::from_le_bytes([data[3], data[4], data[5], 0]);
            let width = 1 + u32::from_le_bytes([data[6], data[7], data[8], 0]);
            let height = 1 + u32::from_le_bytes([data[9], data[10], data[11], 0]);
            if x.checked_add(width).is_none_or(|end| end > canvas_width)
                || y.checked_add(height).is_none_or(|end| end > canvas_height)
            {
                return Err(ImageError::ResourceLimit);
            }
            count = count.checked_add(1).ok_or(ImageError::ResourceLimit)?
        }
        p = chunk_end;
    }
    if p != b.len() {
        return Err(ImageError::Malformed);
    }
    Ok(count)
}

/// Produces an in-memory PNG for encrypted publication as a derived object.
pub fn thumbnail_png(bytes: &[u8], edge: u32) -> Result<SecretBytes, ImageError> {
    let info = probe(bytes)?;
    if edge == 0 || edge > 4096 {
        return Err(ImageError::ResourceLimit);
    }
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| ImageError::Decode)?;
    reader.limits(decoder_limits());
    let decoded = apply_orientation(
        reader.decode().map_err(|_| ImageError::Decode)?,
        info.orientation,
    );
    let scaled = WipeRgba(if decoded.width() > edge || decoded.height() > edge {
        decoded.thumbnail(edge, edge).to_rgba8()
    } else {
        decoded.to_rgba8()
    });
    encode_png_rgba(&scaled.0)
}

fn apply_orientation(
    decoded: image::DynamicImage,
    orientation: Orientation,
) -> image::DynamicImage {
    match orientation {
        Orientation::Normal => decoded,
        Orientation::MirrorHorizontal => decoded.fliph(),
        Orientation::Rotate180 => decoded.rotate180(),
        Orientation::MirrorVertical => decoded.flipv(),
        Orientation::MirrorHorizontalRotate270 => decoded.fliph().rotate270(),
        Orientation::Rotate90 => decoded.rotate90(),
        Orientation::MirrorHorizontalRotate90 => decoded.fliph().rotate90(),
        Orientation::Rotate270 => decoded.rotate270(),
    }
}

fn encode_png_rgba(scaled: &image::RgbaImage) -> Result<SecretBytes, ImageError> {
    let mut encoded = Vec::new();
    PngEncoder::new(&mut encoded)
        .write_image(
            scaled.as_raw(),
            scaled.width(),
            scaled.height(),
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|_| ImageError::Decode)?;
    let protected = SecretBytes::new(&encoded).map_err(|_| ImageError::Decode);
    encoded.zeroize();
    protected
}

fn thumbnail_dimensions(bytes: &[u8]) -> Result<(u32, u32), ImageError> {
    let thumbnail = probe(bytes)?;
    if thumbnail.format != ImageFormat::Png
        || thumbnail.frames != 1
        || thumbnail.orientation != Orientation::Normal
    {
        return Err(ImageError::Malformed);
    }
    Ok((thumbnail.width, thumbnail.height))
}

/// Fully decodes the input and packages allowlisted facts with a derived PNG.
pub fn image_worker_result(bytes: &[u8], edge: u32) -> Result<SecretBytes, ImageError> {
    image_worker_result_for(bytes, ImagePurpose::Thumbnail, edge)
}

fn image_worker_result_for(
    bytes: &[u8],
    purpose: ImagePurpose,
    edge: u32,
) -> Result<SecretBytes, ImageError> {
    let info = probe(bytes)?;
    let thumbnail = thumbnail_png(bytes, edge)?;
    let (thumbnail_width, thumbnail_height) = thumbnail_dimensions(thumbnail.expose())?;
    let rgba = WipeRgba(
        ImageReader::new(std::io::Cursor::new(thumbnail.expose()))
            .with_guessed_format()
            .map_err(|_| ImageError::Decode)?
            .decode()
            .map_err(|_| ImageError::Decode)?
            .to_rgba8(),
    );
    let expected_rgba_len = usize::try_from(
        u64::from(thumbnail_width)
            .checked_mul(u64::from(thumbnail_height))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(ImageError::ResourceLimit)?,
    )
    .map_err(|_| ImageError::ResourceLimit)?;
    if rgba.0.len() != expected_rgba_len {
        return Err(ImageError::Decode);
    }
    let animation = if purpose == ImagePurpose::Viewer && info.frames > 1 {
        animation_frames(bytes, edge)?
    } else {
        Vec::new()
    };
    let output_frames = if animation.is_empty() {
        1
    } else {
        animation.len()
    };
    let first_delay_ms = animation.first().map_or(0, |frame| frame.delay_ms);
    let display_rgba = animation
        .first()
        .map_or(rgba.0.as_raw().as_slice(), |frame| frame.pixels.expose());
    if display_rgba.len() != expected_rgba_len {
        return Err(ImageError::Malformed);
    }
    let mut additional_frames_len = 0usize;
    for frame in animation.iter().skip(1) {
        if frame.width != thumbnail_width
            || frame.height != thumbnail_height
            || frame.pixels.len() != expected_rgba_len
        {
            return Err(ImageError::Malformed);
        }
        additional_frames_len = additional_frames_len
            .checked_add(4)
            .and_then(|length| length.checked_add(frame.pixels.len()))
            .ok_or(ImageError::ResourceLimit)?;
    }
    let total = WORKER_RESULT_HEADER_LEN
        .checked_add(thumbnail.len())
        .and_then(|size| size.checked_add(rgba.0.len()))
        .and_then(|size| size.checked_add(additional_frames_len))
        .filter(|size| {
            *size
                <= match purpose {
                    ImagePurpose::Thumbnail => MAX_THUMBNAIL_RESULT_BYTES,
                    ImagePurpose::Viewer => MAX_VIEWER_RESULT_BYTES,
                }
        })
        .ok_or(ImageError::ResourceLimit)?;
    let mut result = SecretBytes::zeroed(total).map_err(|_| ImageError::Decode)?;
    let header = &mut result.expose_mut()[..WORKER_RESULT_HEADER_LEN];
    header[..8].copy_from_slice(b"OSVIMG4\0");
    header[8..12].copy_from_slice(&info.width.to_le_bytes());
    header[12..16].copy_from_slice(&info.height.to_le_bytes());
    header[16..20].copy_from_slice(&info.frames.to_le_bytes());
    header[20] = info.format as u8;
    header[21] = info.orientation as u8;
    header[22] = u8::from(info.has_color_profile);
    header[23] = purpose as u8;
    header[24..28].copy_from_slice(&THUMBNAIL_RECIPE_VERSION.to_le_bytes());
    header[28..32].copy_from_slice(&thumbnail_width.to_le_bytes());
    header[32..36].copy_from_slice(&thumbnail_height.to_le_bytes());
    let thumbnail_png_len =
        u32::try_from(thumbnail.len()).map_err(|_| ImageError::ResourceLimit)?;
    let rgba_len = u32::try_from(rgba.0.len()).map_err(|_| ImageError::ResourceLimit)?;
    header[36..40].copy_from_slice(&thumbnail_png_len.to_le_bytes());
    header[40..44].copy_from_slice(&rgba_len.to_le_bytes());
    header[44..48].copy_from_slice(&edge.to_le_bytes());
    header[48..52].copy_from_slice(
        &u32::try_from(output_frames)
            .map_err(|_| ImageError::ResourceLimit)?
            .to_le_bytes(),
    );
    header[52..56].copy_from_slice(&first_delay_ms.to_le_bytes());
    header[56..60].copy_from_slice(
        &u32::try_from(additional_frames_len)
            .map_err(|_| ImageError::ResourceLimit)?
            .to_le_bytes(),
    );
    let png_end = WORKER_RESULT_HEADER_LEN + thumbnail.len();
    result.expose_mut()[WORKER_RESULT_HEADER_LEN..png_end].copy_from_slice(thumbnail.expose());
    result.expose_mut()[png_end..png_end + rgba.0.len()].copy_from_slice(display_rgba);
    let mut offset = png_end + rgba.0.len();
    for frame in animation.iter().skip(1) {
        result.expose_mut()[offset..offset + 4].copy_from_slice(&frame.delay_ms.to_le_bytes());
        offset += 4;
        result.expose_mut()[offset..offset + frame.pixels.len()]
            .copy_from_slice(frame.pixels.expose());
        offset += frame.pixels.len();
    }
    Ok(result)
}

pub fn decode_worker_result_header(bytes: &[u8]) -> Result<WorkerImageResult, ImageError> {
    if bytes.len() < WORKER_RESULT_HEADER_LEN
        || &bytes[..8] != b"OSVIMG4\0"
        || bytes[60..64] != [0; 4]
    {
        return Err(ImageError::Malformed);
    }
    let format = match bytes[20] {
        0 => ImageFormat::Png,
        1 => ImageFormat::Jpeg,
        2 => ImageFormat::Gif,
        3 => ImageFormat::Webp,
        _ => return Err(ImageError::Malformed),
    };
    let orientation = match bytes[21] {
        0 => Orientation::Normal,
        1 => Orientation::MirrorHorizontal,
        2 => Orientation::Rotate180,
        3 => Orientation::MirrorVertical,
        4 => Orientation::MirrorHorizontalRotate270,
        5 => Orientation::Rotate90,
        6 => Orientation::MirrorHorizontalRotate90,
        7 => Orientation::Rotate270,
        _ => return Err(ImageError::Malformed),
    };
    let purpose = match bytes[23] {
        1 => ImagePurpose::Thumbnail,
        2 => ImagePurpose::Viewer,
        _ => return Err(ImageError::Malformed),
    };
    let requested_edge = u32::from_le_bytes(
        bytes[44..48]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    encode_worker_request(purpose, requested_edge)?;
    if bytes[22] > 1
        || u32::from_le_bytes(
            bytes[24..28]
                .try_into()
                .map_err(|_| ImageError::Malformed)?,
        ) != THUMBNAIL_RECIPE_VERSION
    {
        return Err(ImageError::Malformed);
    }
    let info = ImageProbe {
        format,
        width: u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| ImageError::Malformed)?),
        height: u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| ImageError::Malformed)?,
        ),
        frames: u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| ImageError::Malformed)?,
        ),
        orientation,
        has_color_profile: bytes[22] == 1,
    };
    let pixels = u64::from(info.width)
        .checked_mul(u64::from(info.height))
        .ok_or(ImageError::ResourceLimit)?;
    let thumbnail_width = u32::from_le_bytes(
        bytes[28..32]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    let thumbnail_height = u32::from_le_bytes(
        bytes[32..36]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    let thumbnail_png_len = u32::from_le_bytes(
        bytes[36..40]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    let rgba_len = u32::from_le_bytes(
        bytes[40..44]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    let expected_rgba_len = thumbnail_width
        .checked_mul(thumbnail_height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(ImageError::ResourceLimit)?;
    let output_frames = u32::from_le_bytes(
        bytes[48..52]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    let first_delay_ms = u32::from_le_bytes(
        bytes[52..56]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    let additional_frames_len = u32::from_le_bytes(
        bytes[56..60]
            .try_into()
            .map_err(|_| ImageError::Malformed)?,
    );
    let expected_additional = output_frames
        .checked_sub(1)
        .and_then(|frames| frames.checked_mul(rgba_len.checked_add(4)?))
        .ok_or(ImageError::ResourceLimit)?;
    if info.width == 0
        || info.height == 0
        || info.frames == 0
        || pixels > MAX_PIXELS
        || thumbnail_width == 0
        || thumbnail_height == 0
        || thumbnail_width > 4096
        || thumbnail_height > 4096
        || thumbnail_png_len == 0
        || rgba_len != expected_rgba_len
        || output_frames == 0
        || output_frames > info.frames
        || additional_frames_len != expected_additional
        || (output_frames == 1 && first_delay_ms != 0)
        || (output_frames > 1 && !(10..=60_000).contains(&first_delay_ms))
    {
        Err(ImageError::ResourceLimit)
    } else {
        Ok(WorkerImageResult {
            source: info,
            thumbnail_width,
            thumbnail_height,
            thumbnail_png_len,
            rgba_len,
            purpose,
            requested_edge,
            output_frames,
            first_delay_ms,
            additional_frames_len,
        })
    }
}

pub struct BoundedCache<K> {
    entries: VecDeque<(K, SecretBytes, usize)>,
    bytes: usize,
    limit: usize,
}
impl<K: Eq> BoundedCache<K> {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            limit,
        }
    }
    pub fn insert(&mut self, key: K, value: SecretBytes) {
        // SecretBytes owns at least one mmap page. Charge the largest Linux
        // base-page size so tiny/empty values cannot amplify locked memory.
        const CONSERVATIVE_PAGE_BYTES: usize = 64 * 1024;
        let charge = value.len().max(CONSERVATIVE_PAGE_BYTES);
        if value.is_empty() || charge > self.limit {
            return;
        }
        if let Some(i) = self.entries.iter().position(|(k, _, _)| k == &key)
            && let Some((_, _, old_charge)) = self.entries.remove(i)
        {
            self.bytes -= old_charge;
        }
        while self.bytes + charge > self.limit {
            if let Some((_, _, old_charge)) = self.entries.pop_front() {
                self.bytes -= old_charge;
            } else {
                break;
            }
        }
        self.bytes += charge;
        self.entries.push_back((key, value, charge))
    }
    pub fn get(&mut self, key: &K) -> Option<&[u8]> {
        let i = self.entries.iter().position(|(k, _, _)| k == key)?;
        let value = self.entries.remove(i)?;
        self.entries.push_back(value);
        self.entries.back().map(|(_, v, _)| v.expose())
    }
    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0
    }
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ViewerState {
    zoom: f64,
    pan_x: f64,
    pan_y: f64,
    rotation: u16,
    playing: bool,
    frame: u32,
    frames: u32,
}
impl ViewerState {
    #[must_use]
    pub fn new(frames: u32) -> Self {
        Self {
            zoom: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            rotation: 0,
            playing: frames > 1,
            frame: 0,
            frames: frames.max(1),
        }
    }
    pub fn zoom_by(&mut self, factor: f64) {
        if factor.is_finite() && factor > 0.0 {
            self.zoom = (self.zoom * factor).clamp(0.05, 64.0)
        }
    }
    pub fn pan_by(&mut self, x: f64, y: f64) {
        if x.is_finite() && y.is_finite() {
            self.pan_x = (self.pan_x + x).clamp(-1e6, 1e6);
            self.pan_y = (self.pan_y + y).clamp(-1e6, 1e6)
        }
    }
    pub fn rotate_clockwise(&mut self) {
        self.rotation = (self.rotation + 90) % 360
    }
    pub fn toggle_animation(&mut self) {
        if self.frames > 1 {
            self.playing = !self.playing
        }
    }
    pub fn advance(&mut self) {
        if self.playing {
            self.frame = (self.frame + 1) % self.frames
        }
    }
    pub fn step_forward(&mut self) {
        self.frame = (self.frame + 1) % self.frames
    }
    #[must_use]
    pub const fn zoom(&self) -> f64 {
        self.zoom
    }
    #[must_use]
    pub const fn rotation(&self) -> u16 {
        self.rotation
    }
    #[must_use]
    pub const fn pan(&self) -> (f64, f64) {
        (self.pan_x, self.pan_y)
    }
    #[must_use]
    pub const fn frame(&self) -> u32 {
        self.frame
    }
    #[must_use]
    pub const fn playing(&self) -> bool {
        self.playing
    }
}

pub fn spawn_worker(
    executable: &Path,
    request_id: u64,
    limits: osv_isolation::SupervisorLimits,
) -> Result<osv_isolation::Supervisor, osv_isolation::SupervisorError> {
    osv_isolation::Supervisor::spawn(
        executable,
        osv_worker_protocol::Role::Media,
        request_id,
        limits,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageEncoder;
    fn png(w: u32, h: u32) -> Vec<u8> {
        fn chunk(target: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
            target.extend(u32::try_from(data.len()).unwrap().to_be_bytes());
            target.extend(kind);
            target.extend(data);
            let mut crc = crc32fast::Hasher::new();
            crc.update(kind);
            crc.update(data);
            target.extend(crc.finalize().to_be_bytes());
        }
        let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut ihdr = Vec::from(w.to_be_bytes());
        ihdr.extend(h.to_be_bytes());
        ihdr.extend([8, 6, 0, 0, 0]);
        chunk(&mut b, b"IHDR", &ihdr);
        chunk(&mut b, b"IDAT", &[]);
        chunk(&mut b, b"IEND", &[]);
        b
    }

    fn rgba_fixture() -> image::RgbaImage {
        image::RgbaImage::from_fn(2, 3, |x, y| {
            image::Rgba([
                u8::try_from(x * 80).unwrap(),
                u8::try_from(y * 60).unwrap(),
                90,
                255,
            ])
        })
    }

    fn jpeg_with_orientation(orientation: u16) -> Vec<u8> {
        let image = rgba_fixture();
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 95)
            .encode_image(&image)
            .unwrap();
        let mut exif = b"Exif\0\0II*\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0".to_vec();
        exif.extend(orientation.to_le_bytes());
        exif.extend([0, 0, 0, 0, 0, 0]);
        let mut segment = vec![0xff, 0xe1];
        segment.extend(u16::try_from(exif.len() + 2).unwrap().to_be_bytes());
        segment.extend(exif);
        jpeg.splice(2..2, segment);
        jpeg
    }

    fn png_with_srgb(mut png: Vec<u8>) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend(1u32.to_be_bytes());
        chunk.extend(b"sRGB");
        chunk.push(0);
        let mut crc = crc32fast::Hasher::new();
        crc.update(b"sRGB");
        crc.update(&[0]);
        chunk.extend(crc.finalize().to_be_bytes());
        png.splice(33..33, chunk);
        png
    }

    fn jpeg_with_icc(mut jpeg: Vec<u8>) -> Vec<u8> {
        let payload = b"ICC_PROFILE\0\x01\x01test-profile";
        let mut segment = vec![0xff, 0xe2];
        segment.extend(u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
        segment.extend(payload);
        jpeg.splice(2..2, segment);
        jpeg
    }

    fn encoded_formats() -> Vec<(ImageFormat, Vec<u8>)> {
        let image = rgba_fixture();
        let mut png = Vec::new();
        PngEncoder::new(&mut png)
            .write_image(image.as_raw(), 2, 3, image::ExtendedColorType::Rgba8)
            .unwrap();
        let jpeg = jpeg_with_orientation(1);
        let mut gif = Vec::new();
        image::codecs::gif::GifEncoder::new(&mut gif)
            .encode(image.as_raw(), 2, 3, image::ExtendedColorType::Rgba8)
            .unwrap();
        let mut simple_webp = Vec::new();
        image::codecs::webp::WebPEncoder::new_lossless(&mut simple_webp)
            .write_image(image.as_raw(), 2, 3, image::ExtendedColorType::Rgba8)
            .unwrap();
        let mut webp = b"RIFF\0\0\0\0WEBPVP8X\x0a\0\0\0\0\0\0\0\x01\0\0\x02\0\0".to_vec();
        webp.extend_from_slice(&simple_webp[12..]);
        let riff_len = u32::try_from(webp.len() - 8).unwrap();
        webp[4..8].copy_from_slice(&riff_len.to_le_bytes());
        vec![
            (ImageFormat::Png, png),
            (ImageFormat::Jpeg, jpeg),
            (ImageFormat::Gif, gif),
            (ImageFormat::Webp, webp),
        ]
    }

    fn animated_webp() -> Vec<u8> {
        fn chunk(output: &mut Vec<u8>, kind: &[u8; 4], payload: &[u8]) {
            output.extend_from_slice(kind);
            output.extend(u32::try_from(payload.len()).unwrap().to_le_bytes());
            output.extend_from_slice(payload);
            if !payload.len().is_multiple_of(2) {
                output.push(0);
            }
        }

        fn lossless_frame(color: [u8; 4], delay_ms: u32) -> Vec<u8> {
            let pixels = color.repeat(4);
            let mut still = Vec::new();
            image::codecs::webp::WebPEncoder::new_lossless(&mut still)
                .write_image(&pixels, 2, 2, image::ExtendedColorType::Rgba8)
                .unwrap();
            let mut payload = vec![0; 16];
            payload[6] = 1;
            payload[9] = 1;
            payload[12..15].copy_from_slice(&delay_ms.to_le_bytes()[..3]);
            payload[15] = 2;
            payload.extend_from_slice(&still[12..]);
            payload
        }

        let mut webp = b"RIFF\0\0\0\0WEBP".to_vec();
        chunk(&mut webp, b"VP8X", &[0x12, 0, 0, 0, 1, 0, 0, 1, 0, 0]);
        chunk(&mut webp, b"ANIM", &[0, 0, 0, 0, 0, 0]);
        chunk(&mut webp, b"ANMF", &lossless_frame([1, 2, 3, 255], 25));
        chunk(&mut webp, b"ANMF", &lossless_frame([4, 5, 6, 255], 50));
        let riff_len = u32::try_from(webp.len() - 8).unwrap();
        webp[4..8].copy_from_slice(&riff_len.to_le_bytes());
        webp
    }
    #[test]
    fn rejects_bomb_before_decode() {
        assert_eq!(probe(&png(65_535, 65_535)), Err(ImageError::ResourceLimit))
    }
    #[test]
    fn probes_png() {
        let p = probe(&png(10, 20)).unwrap();
        assert_eq!(
            (p.format, p.width, p.height, p.frames),
            (ImageFormat::Png, 10, 20, 1)
        )
    }
    #[test]
    fn genuine_allowlisted_formats_decode_under_limits() {
        for (format, bytes) in encoded_formats() {
            assert_eq!(probe(&bytes).unwrap().format, format);
            let result = image_worker_result(&bytes, 512).unwrap();
            let decoded = decode_worker_result_header(result.expose()).unwrap();
            assert_eq!(decoded.source.format, format);
            assert_eq!((decoded.thumbnail_width, decoded.thumbnail_height), (2, 3));
        }
    }
    #[test]
    fn all_exif_orientations_are_applied_before_thumbnail_geometry() {
        for orientation in 1..=8 {
            let bytes = jpeg_with_orientation(orientation);
            let result = image_worker_result(&bytes, 512).unwrap();
            let decoded = decode_worker_result_header(result.expose()).unwrap();
            let expected = if orientation >= 5 { (3, 2) } else { (2, 3) };
            assert_eq!(
                (decoded.thumbnail_width, decoded.thumbnail_height),
                expected,
                "orientation {orientation}"
            );
        }
    }
    #[test]
    fn all_exif_orientations_have_exact_pixel_mapping() {
        let source = image::RgbaImage::from_fn(2, 3, |x, y| {
            image::Rgba([u8::try_from(y * 2 + x + 1).unwrap(), 0, 0, 255])
        });
        let cases: [(Orientation, &[u8]); 8] = [
            (Orientation::Normal, &[1, 2, 3, 4, 5, 6]),
            (Orientation::MirrorHorizontal, &[2, 1, 4, 3, 6, 5]),
            (Orientation::Rotate180, &[6, 5, 4, 3, 2, 1]),
            (Orientation::MirrorVertical, &[5, 6, 3, 4, 1, 2]),
            (Orientation::MirrorHorizontalRotate270, &[1, 3, 5, 2, 4, 6]),
            (Orientation::Rotate90, &[5, 3, 1, 6, 4, 2]),
            (Orientation::MirrorHorizontalRotate90, &[6, 4, 2, 5, 3, 1]),
            (Orientation::Rotate270, &[2, 4, 6, 1, 3, 5]),
        ];
        for (orientation, expected) in cases {
            let oriented =
                apply_orientation(image::DynamicImage::ImageRgba8(source.clone()), orientation)
                    .to_rgba8();
            let actual: Vec<_> = oriented.pixels().map(|pixel| pixel[0]).collect();
            assert_eq!(actual, expected, "{orientation:?}");
        }
    }
    #[test]
    fn srgb_profile_presence_does_not_transform_display_pixels() {
        let plain = encoded_formats().remove(0).1;
        let profiled = png_with_srgb(plain.clone());
        assert!(!probe(&plain).unwrap().has_color_profile);
        assert!(probe(&profiled).unwrap().has_color_profile);
        let plain_thumbnail = thumbnail_png(&plain, 512).unwrap();
        let profiled_thumbnail = thumbnail_png(&profiled, 512).unwrap();
        assert_eq!(plain_thumbnail.expose(), profiled_thumbnail.expose());
    }
    #[test]
    fn jpeg_icc_presence_does_not_transform_display_pixels() {
        let plain = jpeg_with_orientation(1);
        let profiled = jpeg_with_icc(plain.clone());
        assert!(!probe(&plain).unwrap().has_color_profile);
        assert!(probe(&profiled).unwrap().has_color_profile);
        let plain_thumbnail = thumbnail_png(&plain, 512).unwrap();
        let profiled_thumbnail = thumbnail_png(&profiled, 512).unwrap();
        assert_eq!(plain_thumbnail.expose(), profiled_thumbnail.expose());
    }
    #[test]
    fn corrupt_png_crc_and_truncation_are_rejected() {
        let mut corrupt = png(10, 20);
        corrupt[29] ^= 1;
        assert_eq!(probe(&corrupt), Err(ImageError::Malformed));
        let truncated = &png(10, 20)[..40];
        assert_eq!(probe(truncated), Err(ImageError::Malformed));
    }

    #[test]
    fn png_chunk_order_and_webp_reserved_fields_are_rejected_by_probe() {
        fn insert_png_chunk(png: &mut Vec<u8>, offset: usize, kind: &[u8; 4], data: &[u8]) {
            let mut chunk = Vec::new();
            chunk.extend(u32::try_from(data.len()).unwrap().to_be_bytes());
            chunk.extend(kind);
            chunk.extend(data);
            let mut crc = crc32fast::Hasher::new();
            crc.update(kind);
            crc.update(data);
            chunk.extend(crc.finalize().to_be_bytes());
            png.splice(offset..offset, chunk);
        }

        let valid_png = encoded_formats().remove(0).1;
        let mut duplicate_header = valid_png.clone();
        let ihdr = valid_png[16..29].to_vec();
        insert_png_chunk(&mut duplicate_header, 33, b"IHDR", &ihdr);
        assert_eq!(probe(&duplicate_header), Err(ImageError::Malformed));

        let mut late_animation_control = valid_png;
        let idat_end = 33
            + 12
            + usize::try_from(u32::from_be_bytes(
                late_animation_control[33..37].try_into().unwrap(),
            ))
            .unwrap();
        insert_png_chunk(
            &mut late_animation_control,
            idat_end,
            b"acTL",
            &[0, 0, 0, 1, 0, 0, 0, 0],
        );
        assert_eq!(probe(&late_animation_control), Err(ImageError::Malformed));

        let mut reserved_webp_flag = encoded_formats().remove(3).1;
        reserved_webp_flag[20] |= 0x80;
        assert_eq!(probe(&reserved_webp_flag), Err(ImageError::Malformed));

        let mut reserved_webp_header = encoded_formats().remove(3).1;
        reserved_webp_header[21] = 1;
        assert_eq!(probe(&reserved_webp_header), Err(ImageError::Malformed));
    }
    #[test]
    fn truncated_jpeg_gif_and_webp_fail_complete_decode() {
        for (format, mut bytes) in encoded_formats().into_iter().skip(1) {
            let remove = (bytes.len() / 3).max(1);
            bytes.truncate(bytes.len() - remove);
            assert!(
                image_worker_result(&bytes, THUMBNAIL_EDGE).is_err(),
                "{format:?} truncation decoded"
            );
        }
    }

    #[test]
    fn gif_trailer_and_webp_riff_framing_are_required_by_probe() {
        let mut gif = encoded_formats().remove(2).1;
        assert_eq!(gif.pop(), Some(0x3b));
        assert_eq!(probe(&gif), Err(ImageError::Malformed));

        let mut trailing_webp = encoded_formats().remove(3).1;
        trailing_webp.push(0);
        assert_eq!(probe(&trailing_webp), Err(ImageError::Malformed));

        let mut short_riff = encoded_formats().remove(3).1;
        let declared = u32::try_from(short_riff.len() - 9).unwrap();
        short_riff[4..8].copy_from_slice(&declared.to_le_bytes());
        assert_eq!(probe(&short_riff), Err(ImageError::Malformed));

        let mut truncated_chunk = encoded_formats().remove(3).1;
        truncated_chunk.pop();
        let declared = u32::try_from(truncated_chunk.len() - 8).unwrap();
        truncated_chunk[4..8].copy_from_slice(&declared.to_le_bytes());
        assert_eq!(probe(&truncated_chunk), Err(ImageError::Malformed));
    }

    #[test]
    fn malformed_gif_extensions_fail_before_decode() {
        fn insert_extension(extension: &[u8]) -> Vec<u8> {
            let mut gif = encoded_formats().remove(2).1;
            let color_table_len = if gif[10] & 0x80 == 0 {
                0
            } else {
                3 * (1usize << (usize::from(gif[10] & 7) + 1))
            };
            gif.splice(
                13 + color_table_len..13 + color_table_len,
                extension.iter().copied(),
            );
            gif
        }

        for extension in [
            vec![0x21, 0x02, 0],
            vec![0x21, 0xf9, 3, 0, 0, 0, 0, 0],
            vec![0x21, 0xf9, 4, 0xe0, 0, 0, 0, 0],
            [vec![0x21, 0xff, 10], vec![0; 10], vec![0]].concat(),
            vec![0x21, 0xfe, 2, 1],
        ] {
            assert_eq!(
                probe(&insert_extension(&extension)),
                Err(ImageError::Malformed)
            );
        }
    }
    #[test]
    fn cache_evicts_and_clears() {
        let mut c = BoundedCache::new(65_536);
        c.insert(1, SecretBytes::new(b"123").unwrap());
        c.insert(2, SecretBytes::new(b"456").unwrap());
        assert!(c.get(&1).is_none());
        assert_eq!(c.bytes(), 65_536);
        c.clear();
        assert_eq!(c.bytes(), 0)
    }

    #[test]
    fn application_owned_rgba_is_wiped_before_release() {
        let mut rgba = WipeRgba(image::RgbaImage::from_pixel(
            2,
            2,
            image::Rgba([1, 2, 3, 4]),
        ));
        rgba.wipe();
        assert!(rgba.0.as_raw().iter().all(|byte| *byte == 0));
    }
    #[test]
    fn viewer_bounds_animation() {
        let mut v = ViewerState::new(2);
        v.zoom_by(1e9);
        v.rotate_clockwise();
        v.advance();
        assert_eq!((v.zoom(), v.rotation(), v.frame()), (64.0, 90, 1));
        v.toggle_animation();
        assert!(!v.playing());
        v.step_forward();
        assert_eq!(v.frame(), 0);
        v.pan_by(12.0, -7.0);
        assert_eq!(v.pan(), (12.0, -7.0));
    }

    #[test]
    fn real_png_decodes_to_worker_result() {
        let image = image::RgbaImage::from_pixel(2, 3, image::Rgba([0x33, 0x66, 0x99, 0xff]));
        let mut encoded = Vec::new();
        PngEncoder::new(&mut encoded)
            .write_image(image.as_raw(), 2, 3, image::ExtendedColorType::Rgba8)
            .unwrap();
        let result = image_worker_result(&encoded, 512).unwrap();
        assert_eq!(
            decode_worker_result_header(result.expose())
                .unwrap()
                .source
                .width,
            2
        );
    }

    #[test]
    fn rendition_request_binds_purpose_and_edge() {
        let image = encoded_formats().remove(0).1;
        let mut request = encode_worker_request(ImagePurpose::Viewer, 2048)
            .unwrap()
            .to_vec();
        request.extend_from_slice(&image);
        let result = image_worker_result_from_request(&request).unwrap();
        let header = decode_worker_result_header(result.expose()).unwrap();
        assert_eq!(header.purpose, ImagePurpose::Viewer);
        assert_eq!(header.requested_edge, 2048);
        request[9] = 1;
        assert!(matches!(
            image_worker_result_from_request(&request),
            Err(ImageError::Malformed)
        ));
        assert!(encode_worker_request(ImagePurpose::Thumbnail, 513).is_err());
        assert!(encode_worker_request(ImagePurpose::Viewer, 4097).is_err());
    }

    #[test]
    fn animated_gif_frames_are_full_canvas_timed_and_protected() {
        let first = image::RgbaImage::from_pixel(3, 2, image::Rgba([1, 2, 3, 255]));
        let second = image::RgbaImage::from_pixel(3, 2, image::Rgba([4, 5, 6, 255]));
        let frames = [
            image::Frame::from_parts(first, 0, 0, image::Delay::from_numer_denom_ms(25, 1)),
            image::Frame::from_parts(second, 0, 0, image::Delay::from_numer_denom_ms(50, 1)),
        ];
        let mut encoded = Vec::new();
        image::codecs::gif::GifEncoder::new(&mut encoded)
            .encode_frames(frames)
            .unwrap();
        let decoded = animation_frames(&encoded, 512).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!((decoded[0].width, decoded[0].height), (3, 2));
        assert_eq!((decoded[0].delay_ms, decoded[1].delay_ms), (20, 50));
        assert_eq!(decoded[0].pixels.expose()[..4], [1, 2, 3, 255]);
        assert!(!format!("{decoded:?}").contains("1, 2, 3"));

        let mut request = encode_worker_request(ImagePurpose::Viewer, 512)
            .unwrap()
            .to_vec();
        request.extend_from_slice(&encoded);
        let result = image_worker_result_from_request(&request).unwrap();
        let header = decode_worker_result_header(result.expose()).unwrap();
        assert_eq!(header.output_frames, 2);
        assert_eq!(header.first_delay_ms, 20);
        assert_eq!(header.additional_frames_len, 4 + 3 * 2 * 4);
        assert_eq!(
            result.len(),
            WORKER_RESULT_HEADER_LEN
                + usize::try_from(header.thumbnail_png_len).unwrap()
                + usize::try_from(header.rgba_len).unwrap()
                + usize::try_from(header.additional_frames_len).unwrap()
        );
    }

    #[test]
    fn hostile_animation_result_headers_fail_closed() {
        let frames = [
            image::Frame::from_parts(
                image::RgbaImage::from_pixel(2, 2, image::Rgba([1, 2, 3, 255])),
                0,
                0,
                image::Delay::from_numer_denom_ms(20, 1),
            ),
            image::Frame::from_parts(
                image::RgbaImage::from_pixel(2, 2, image::Rgba([4, 5, 6, 255])),
                0,
                0,
                image::Delay::from_numer_denom_ms(30, 1),
            ),
        ];
        let mut encoded = Vec::new();
        image::codecs::gif::GifEncoder::new(&mut encoded)
            .encode_frames(frames)
            .unwrap();
        let mut request = encode_worker_request(ImagePurpose::Viewer, 512)
            .unwrap()
            .to_vec();
        request.extend_from_slice(&encoded);
        let valid = image_worker_result_from_request(&request).unwrap();
        for mutate in [
            (48usize, [3, 0, 0, 0]),
            (52, [0, 0, 0, 0]),
            (56, [1, 0, 0, 0]),
            (60, [1, 0, 0, 0]),
        ] {
            let mut hostile = valid.expose().to_vec();
            hostile[mutate.0..mutate.0 + 4].copy_from_slice(&mutate.1);
            assert!(decode_worker_result_header(&hostile).is_err());
            hostile.zeroize();
        }
    }

    #[test]
    fn genuine_apng_decodes_full_canvas_frames_and_timing() {
        let mut encoded = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut encoded, 2, 2);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder.set_animated(2, 0).unwrap();
            encoder.validate_sequence(true);
            let mut writer = encoder.write_header().unwrap();
            writer.set_frame_delay(1, 10).unwrap();
            writer.write_image_data(&[1, 2, 3, 255].repeat(4)).unwrap();
            writer.set_frame_delay(1, 20).unwrap();
            writer.write_image_data(&[4, 5, 6, 255].repeat(4)).unwrap();
            writer.finish().unwrap();
        }
        let probe = probe(&encoded).unwrap();
        assert_eq!((probe.format, probe.frames), (ImageFormat::Png, 2));
        let frames = animation_frames(&encoded, 512).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!((frames[0].width, frames[0].height), (2, 2));
        assert_eq!((frames[0].delay_ms, frames[1].delay_ms), (100, 50));
        assert_eq!(frames[0].pixels.expose()[..4], [1, 2, 3, 255]);
        assert_eq!(frames[1].pixels.expose()[..4], [4, 5, 6, 255]);
        let mut request = encode_worker_request(ImagePurpose::Viewer, 512)
            .unwrap()
            .to_vec();
        request.extend_from_slice(&encoded);
        let result = image_worker_result_from_request(&request).unwrap();
        let header = decode_worker_result_header(result.expose()).unwrap();
        assert_eq!((header.source.frames, header.output_frames), (2, 2));
    }

    #[test]
    fn apng_sequence_geometry_and_frame_count_fail_before_decode() {
        fn encoded_apng() -> Vec<u8> {
            let mut encoded = Vec::new();
            let mut encoder = png::Encoder::new(&mut encoded, 2, 2);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder.set_animated(2, 0).unwrap();
            encoder.validate_sequence(true);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&[1, 2, 3, 255].repeat(4)).unwrap();
            writer.write_image_data(&[4, 5, 6, 255].repeat(4)).unwrap();
            writer.finish().unwrap();
            encoded
        }

        fn mutate_chunk(bytes: &mut [u8], kind: &[u8; 4], data_offset: usize, value: u8) {
            let mut p = 8usize;
            loop {
                let len = usize::try_from(u32::from_be_bytes(bytes[p..p + 4].try_into().unwrap()))
                    .unwrap();
                let end = p + 12 + len;
                if &bytes[p + 4..p + 8] == kind {
                    bytes[p + 8 + data_offset] = value;
                    let mut crc = crc32fast::Hasher::new();
                    crc.update(kind);
                    crc.update(&bytes[p + 8..end - 4]);
                    bytes[end - 4..end].copy_from_slice(&crc.finalize().to_be_bytes());
                    return;
                }
                p = end;
            }
        }

        let mut wrong_count = encoded_apng();
        mutate_chunk(&mut wrong_count, b"acTL", 3, 3);
        assert_eq!(probe(&wrong_count), Err(ImageError::Malformed));

        let mut wrong_sequence = encoded_apng();
        mutate_chunk(&mut wrong_sequence, b"fcTL", 3, 1);
        assert_eq!(probe(&wrong_sequence), Err(ImageError::Malformed));

        let mut outside_canvas = encoded_apng();
        mutate_chunk(&mut outside_canvas, b"fcTL", 7, 3);
        assert_eq!(probe(&outside_canvas), Err(ImageError::Malformed));

        let mut invalid_disposal = encoded_apng();
        mutate_chunk(&mut invalid_disposal, b"fcTL", 24, 3);
        assert_eq!(probe(&invalid_disposal), Err(ImageError::Malformed));

        let mut invalid_blend = encoded_apng();
        mutate_chunk(&mut invalid_blend, b"fcTL", 25, 2);
        assert_eq!(probe(&invalid_blend), Err(ImageError::Malformed));

        let mut wrong_data_sequence = encoded_apng();
        mutate_chunk(&mut wrong_data_sequence, b"fdAT", 3, 9);
        assert_eq!(probe(&wrong_data_sequence), Err(ImageError::Malformed));
    }

    #[test]
    fn apng_separate_default_image_is_not_a_playback_frame() {
        let mut encoded = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut encoded, 2, 2);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder.set_animated(2, 0).unwrap();
            encoder.set_sep_def_img(true).unwrap();
            encoder.validate_sequence(true);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&[9, 9, 9, 255].repeat(4)).unwrap();
            writer.set_frame_delay(1, 10).unwrap();
            writer.write_image_data(&[1, 2, 3, 255].repeat(4)).unwrap();
            writer.set_frame_delay(1, 20).unwrap();
            writer.write_image_data(&[4, 5, 6, 255].repeat(4)).unwrap();
            writer.finish().unwrap();
        }
        let frames = animation_frames(&encoded, 512).unwrap();
        assert_eq!(frames[0].pixels.expose()[..4], [1, 2, 3, 255]);
        let mut request = encode_worker_request(ImagePurpose::Viewer, 512)
            .unwrap()
            .to_vec();
        request.extend_from_slice(&encoded);
        let result = image_worker_result_from_request(&request).unwrap();
        let header = decode_worker_result_header(result.expose()).unwrap();
        let first_pixel =
            WORKER_RESULT_HEADER_LEN + usize::try_from(header.thumbnail_png_len).unwrap();
        assert_eq!(
            result.expose()[first_pixel..first_pixel + 4],
            [1, 2, 3, 255]
        );
    }

    #[test]
    fn genuine_animated_webp_decodes_full_canvas_frames_and_timing() {
        let encoded = animated_webp();
        let probe = probe(&encoded).unwrap();
        assert_eq!((probe.format, probe.frames), (ImageFormat::Webp, 2));
        let frames = animation_frames(&encoded, 512).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!((frames[0].width, frames[0].height), (2, 2));
        assert_eq!((frames[0].delay_ms, frames[1].delay_ms), (25, 50));
        assert_eq!(frames[0].pixels.expose()[..4], [1, 2, 3, 255]);
        assert_eq!(frames[1].pixels.expose()[..4], [4, 5, 6, 255]);

        let mut request = encode_worker_request(ImagePurpose::Viewer, 512)
            .unwrap()
            .to_vec();
        request.extend_from_slice(&encoded);
        let result = image_worker_result_from_request(&request).unwrap();
        let header = decode_worker_result_header(result.expose()).unwrap();
        assert_eq!((header.source.frames, header.output_frames), (2, 2));
        assert_eq!(
            (header.first_delay_ms, header.additional_frames_len),
            (25, 20)
        );
    }

    #[test]
    fn animated_webp_structure_and_cumulative_pressure_fail_before_decode() {
        let valid = animated_webp();
        let second = valid
            .windows(4)
            .enumerate()
            .filter(|(_, bytes)| *bytes == b"ANMF")
            .nth(1)
            .unwrap()
            .0;
        let mut outside_canvas = valid.clone();
        outside_canvas[second + 8 + 6..second + 8 + 9].copy_from_slice(&[2, 0, 0]);
        assert_eq!(probe(&outside_canvas), Err(ImageError::ResourceLimit));

        let mut truncated = valid.clone();
        truncated.pop();
        assert_eq!(probe(&truncated), Err(ImageError::Malformed));

        let first = valid.windows(4).position(|bytes| bytes == b"ANMF").unwrap();
        let frame_len = 8 + usize::try_from(u32::from_le_bytes(
            valid[first + 4..first + 8].try_into().unwrap(),
        ))
        .unwrap();
        let frame = valid[first..first + frame_len].to_vec();
        let mut pressure = valid[..first].to_vec();
        pressure[24..27].copy_from_slice(&999u32.to_le_bytes()[..3]);
        pressure[27..30].copy_from_slice(&999u32.to_le_bytes()[..3]);
        for _ in 0..201 {
            pressure.extend_from_slice(&frame);
        }
        let riff_len = u32::try_from(pressure.len() - 8).unwrap();
        pressure[4..8].copy_from_slice(&riff_len.to_le_bytes());
        assert_eq!(probe(&pressure), Err(ImageError::ResourceLimit));
    }
}
