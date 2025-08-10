use jni::JNIEnv;
use jni::objects::{JClass, JByteArray};
use jni::sys::{jlong, jboolean, jint};
use openssl::symm::{Cipher, Crypter, Mode};

// Utility function to throw a Java exception
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
    // Get the key bytes
    let key_len = env.get_array_length(&key).unwrap();
    if key_len != 16 {
        throw_exception(&mut env, "java/lang/IllegalArgumentException", "cipher key not 16 bytes");
        return 0;
    }

    // Convert the Java byte array to a Rust Vec<u8>
    let key_bytes = env.convert_byte_array(&key).unwrap();

    // Create the crypter
    let mode = if encrypt != 0 { Mode::Encrypt } else { Mode::Decrypt };
    let cipher = Cipher::aes_128_cfb8();

    // In Minecraft, the key is also used as the IV (as noted in the C implementation)
    match Crypter::new(cipher, mode, &key_bytes, Some(&key_bytes)) {
        Ok(crypter) => {
            // Box the crypter and return a pointer to it
            let boxed = Box::new(crypter);
            Box::into_raw(boxed) as jlong
        }
        Err(_) => {
            throw_exception(&mut env, "java/security/GeneralSecurityException", "openssl initialize cipher");
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

    // Process the data
    let mut count = 0;
    if let Ok(update_len) = crypter.update(src_buf, &mut dst_buf[count..]) {
        count += update_len;
    }

    // If there's any remaining data, finalize it
    if count < len as usize {
        if let Ok(final_len) = crypter.finalize(&mut dst_buf[count..]) {
            count += final_len;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_velocitypowered_natives_encryption_OpenSslCipherImpl_free(
    mut _env: JNIEnv,
    _class: JClass,
    ctx: jlong,
) {
    if ctx != 0 {
        unsafe {
            let _ = Box::from_raw(ctx as *mut Crypter);
        }
    }
}
