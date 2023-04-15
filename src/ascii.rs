use termion::color;

pub fn print_art() {
    let art = r#"9
                     'K0p          .KKp
                      VPPWmm##mmww,KKK
                   ,gKKDH|$]B@@@@5DK#W,
                 z#KHKNKDD#"``""]DKU@|KKw
          'KK#mp#KH$KM` 9  yg#@Ww_  9 *KH$8K,
           `*KU$Nm#N  9  ,KM'  `"Km  9  TNHIKmKKUN
              KHP#KM  9  ]K      ]K   9 1HNh5DMf"
             j]PhM   9 jKKKKKKKKKKKKm  9 "]HDKL
             ]##8N   9 ]KKKKMl "KKKKK  9  ]HH$N
             J#@PKm  9 ]KKKKN- aKKKKK  9 _#HhKM
          ,w#KPNh5NM 9 ]KKKKKNw#KKKKK 9 /UD@]K
          KKMM"5N$0N_ 9`MKKKKKKKKKKM* 9 #HPVUb]Nw
                YNm@XNwwp_       ,_z#KH$KM "*K*
                  YBU@5DKNmwwww#KKDHKN0M-
                    "U0NNp@@@]N@p#KKM^
                   .KKK^ """""""'KpK
                    KM            KKM
    "#;

    let mut color_iter = [ "black", "yellow" ].iter().cycle();
    for c in art.chars() {
        if c == '9' {
            match *color_iter.next().unwrap() {
                "red" => print!("{}", color::Fg(color::Red)),
                "yellow" => print!("{}", color::Fg(color::LightYellow)),
                "black" => print!("{}", color::Fg(color::LightBlack)),
                "reset" => print!("{}", color::Fg(color::Reset)),
                _ => println!("Color not found"),
            };
        } else {
            print!("{}", c);
        }
    }
    println!("{}", color::Fg(color::Reset));
}
