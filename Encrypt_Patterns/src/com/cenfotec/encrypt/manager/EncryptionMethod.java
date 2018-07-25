package com.cenfotec.encrypt.manager;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Base64.Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public abstract class EncryptionMethod {
	protected final String KEY_EXTENSION = ".key";
	protected final String MESSAGE_ENCRYPT_EXTENSION = ".encript";
	
	public abstract void createKey(String name) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, Exception;
	public abstract void encryptMessage(String messageName,String message, String keyName) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;
	public abstract void decryptMessage(String messageName,String keyName) throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, Exception;
	
	protected void writeBytesFile(String name, byte[] content, String type, String PATH) throws FileNotFoundException, IOException {
		FileOutputStream fos = new FileOutputStream(PATH + name + type);
		fos.write(content);
		fos.close();
	}
	
	protected byte[] readMessageFile(String messageName,String PATH) throws Exception{
		File file = new File(PATH + messageName + MESSAGE_ENCRYPT_EXTENSION);
        int length = (int) file.length();
        BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file));
        byte[] bytes = new byte[length];
        reader.read(bytes, 0, length);
        Decoder oneDecoder = Base64.getDecoder();
	    reader.close();
		return oneDecoder.decode(bytes);
	}

}
