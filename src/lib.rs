use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jint, jlong};
use openssl::symm::{Cipher, Crypter, Mode};

fn throw_exception(env: &mut JNIEnv, exception_type: &str, message: &str) {
    let exception_class = env.find_class(exception_type).unwrap();
    env.throw_new(exception_class, message).unwrap();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_velocitypowered_natives_encryption_OpenSslCipherImpl_init(
    mut env: JNIEnv,
    _class: JClass,
    key: JByteArray,
    encrypt: jboolean,
) -> jlong {
    let key_len = match env.get_array_length(&key) {
        Ok(len) => len,
        Err(_) => {
            throw_exception(
                &mut env,
                "java/lang/RuntimeException",
                "Failed to get array length",
            );
            return 0;
        }
    };
    if key_len != 16 {
        throw_exception(
            &mut env,
            "java/lang/IllegalArgumentException",
            "cipher key not 16 bytes",
        );
        return 0;
    }

    let key_bytes = match env.convert_byte_array(&key) {
        Ok(bytes) => bytes,
        Err(_) => {
            throw_exception(
                &mut env,
                "java/lang/RuntimeException",
                "Failed to convert byte array",
            );
            return 0;
        }
    };

    let mode = if encrypt != 0 {
        Mode::Encrypt
    } else {
        Mode::Decrypt
    };
    let cipher = Cipher::aes_128_cfb8();

    match Crypter::new(cipher, mode, &key_bytes, Some(&key_bytes)) {
        Ok(crypter) => {
            let boxed = Box::new(crypter);
            Box::into_raw(boxed) as jlong
        }
        Err(_) => {
            throw_exception(
                &mut env,
                "java/security/GeneralSecurityException",
                "openssl initialize cipher",
            );
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_velocitypowered_natives_encryption_OpenSslCipherImpl_process(
    mut _env: JNIEnv,
    _class: JClass,
    ctx: jlong,
    source: jlong,
    len: jint,
    dest: jlong,
) {
    if ctx == 0 || source == 0 || dest == 0 || len <= 0 {
        return;
    }

    let crypter = unsafe { &mut *(ctx as *mut Crypter) };
    let src_buf = unsafe { std::slice::from_raw_parts(source as *const u8, len as usize) };
    let dst_buf = unsafe { std::slice::from_raw_parts_mut(dest as *mut u8, len as usize) };

    let update_len = if let Ok(len) = crypter.update(src_buf, dst_buf) {
        len
    } else {
        0
    };

    if update_len < len as usize {
        let _ = crypter.finalize(&mut dst_buf[update_len..]);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_velocitypowered_natives_encryption_OpenSslCipherImpl_free(
    mut _env: JNIEnv,
    _class: JClass,
    ctx: jlong,
) {
    unsafe {
        if ctx != 0 {
            let _ = Box::from_raw(ctx as *mut Crypter);
        }
    }
}
