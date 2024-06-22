#[macro_export]
macro_rules! def_enum {
    ($vis:vis $name:ident => $ty:ty {
        $($variant:ident => $val:expr),+
        $(,)?
    }) => {
        $vis struct $name;

        impl $name {
            $(
                pub const $variant: $ty = $val;
            )+

            #[allow(dead_code)]
            pub const VARIANTS: &'static [$ty] = &[$(Self::$variant),+];
        }
    };
}

#[macro_export]
macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

#[macro_export]
macro_rules! hex_dump {
    ($value:expr) => {
        if log::log_enabled!(log::Level::Trace) {
            let name = stringify!($value).split('.').last().unwrap();
            trace!("{}: \n{}", name, pretty_hex::pretty_hex(&$value));
        }
    };
}
