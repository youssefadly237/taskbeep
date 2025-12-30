use hound::{SampleFormat, WavSpec, WavWriter};
use std::{f32::consts::PI, io::Cursor};

const SAMPLE_RATE: u32 = 44100;
const BEEP_FREQUENCY_HZ: f32 = 2048.0;
const FIRST_BEEP_DURATION_S: f32 = 0.08;
const SECOND_BEEP_DURATION_S: f32 = 0.12;
const GAP_DURATION_S: f32 = 0.09;
const PAUSE_DURATION_S: f32 = 0.7;
const VOLUME: f32 = 0.4;
const FADE_DURATION_S: f32 = 0.005;
const BITS_PER_SAMPLE: u16 = 16;
const MAX_AMPLITUDE: f32 = 32767.0;

fn gen_beep(freq: f32, dur: f32, vol: f32, sr: u32) -> Vec<i16> {
    let num_samples = (sr as f32 * dur) as usize;
    let mut wave_data = Vec::with_capacity(num_samples);

    for i in 0..num_samples {
        let t = i as f32 / sr as f32;
        let sample = (2.0 * PI * freq * t).sin();
        wave_data.push(sample);
    }

    let fade_len = (sr as f32 * FADE_DURATION_S) as usize;

    for (i, sample) in wave_data
        .iter_mut()
        .enumerate()
        .take(fade_len.min(num_samples))
    {
        let fade = i as f32 / fade_len as f32;
        *sample *= fade;
    }

    let fade_start = num_samples.saturating_sub(fade_len);
    for (i, sample) in wave_data.iter_mut().enumerate().skip(fade_start) {
        let fade = (num_samples - 1 - i) as f32 / fade_len as f32;
        *sample *= fade;
    }

    wave_data
        .iter()
        .map(|&sample| (sample * vol * MAX_AMPLITUDE) as i16)
        .collect()
}

pub fn generate_beep_audio() -> Vec<u8> {
    let beep1 = gen_beep(
        BEEP_FREQUENCY_HZ,
        FIRST_BEEP_DURATION_S,
        VOLUME,
        SAMPLE_RATE,
    );
    let gap = vec![0i16; (SAMPLE_RATE as f32 * GAP_DURATION_S) as usize];
    let beep2 = gen_beep(
        BEEP_FREQUENCY_HZ,
        SECOND_BEEP_DURATION_S,
        VOLUME,
        SAMPLE_RATE,
    );

    let mut pattern = Vec::new();
    pattern.extend_from_slice(&beep1);
    pattern.extend_from_slice(&gap);
    pattern.extend_from_slice(&beep2);

    let pause = vec![0i16; (SAMPLE_RATE as f32 * PAUSE_DURATION_S) as usize];

    let mut audio = Vec::new();
    audio.extend_from_slice(&pattern);
    audio.extend_from_slice(&pause);

    let spec = WavSpec {
        channels: 1,
        sample_rate: SAMPLE_RATE,
        bits_per_sample: BITS_PER_SAMPLE,
        sample_format: SampleFormat::Int,
    };

    let mut cursor = Cursor::new(Vec::new());
    if let Ok(mut writer) = WavWriter::new(&mut cursor, spec) {
        for sample in audio {
            let _ = writer.write_sample(sample);
        }
        let _ = writer.finalize();
    }

    cursor.into_inner()
}
