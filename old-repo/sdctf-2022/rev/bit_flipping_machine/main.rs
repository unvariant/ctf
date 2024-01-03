fn main() {
    let target: Vec<char> = String::from("rm -rf ///////").chars().collect();
    let mut change: Vec<char> = String::from("rm -rf /trash/").chars().collect();
    let mut ret = String::new();

    for i in 0..(change.len()) {
        for s in (0..8).rev() {
            let n = change[i] as u8;
            if (n >> s) & 1 != (target[i] as u8 >> s) & 1 {
                let t = i as u8 * 8 + 7 - s;
                let ch0 = t / 26;
                let ch1 = t - ch0 * 26;
                ret.push((65 + ch0) as char);
                ret.push((65 + ch1) as char);
            }
        }
    }

    let mut chars: Vec<char> = ret.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let ch0 = chars[i];
        let ch1 = chars[i+1];

        let n = (ch0 as u8 - 65) * 26 + ch1 as u8 - 65;
        let idx = (n / 8) as usize;
        let ch = change[idx] as u8;
        change[idx] = (ch ^ (0b10000000 >> (n % 8))) as char;
    }

    println!("{:?}", change);
    println!("{}", ret);
    println!("{}", ret.len());
}