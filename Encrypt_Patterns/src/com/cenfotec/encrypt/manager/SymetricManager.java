package com.cenfotec.encrypt.manager;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class SymetricManager extends EncryptionMethod{

	private final int KEYSIZE = 8;
	private final String PATH = "C:/encrypt/symetric/";
	
	@Override
	public void createKey(String name) throws Exception {
		byte [] key = generatedSequenceOfBytes();
		writeBytesFile(name,key,KEY_EXTENSION,PATH);
		
	}

	@Override
	public String encryptMessage(String messageName, String message, String keyName) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] key = readKeyFile(keyName);
		Cipher cipher = Cipher.getInstance("AES");
		SecretKeySpec k = new SecretKeySpec(key,"AES");
		cipher.init(Cipher.ENCRYPT_MODE, k);
		byte[] encryptedData = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
	    Encoder oneEncoder = Base64.getEncoder();
	    encryptedData = oneEncoder.encode(encryptedData);
		writeBytesFile(messageName,encryptedData,MESSAGE_ENCRYPT_EXTENSION,PATH);
		return new String(encryptedData, StandardCharsets.UTF_8);
	}

	private byte[] readKeyFile(String keyName) throws FileNotFoundException, IOException {
		BufferedReader br = new BufferedReader(new FileReader(PATH + keyName + KEY_EXTENSION));
		String everything = "";
		try {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();

		    while (line != null) {
		        sb.append(line);
		        line = br.readLine();
		    }
		    everything = sb.toString();
		} finally {
		    br.close();
		}
		return everything.getBytes(StandardCharsets.UTF_8);
	}
	
	@Override
	public String decryptMessage(String messageName, String keyName) throws Exception {
		byte[] key = readKeyFile(keyName);
		byte[] encryptedMessage = readMessageFile(messageName,PATH);
		System.out.println(encryptedMessage.length);
		Cipher cipher = Cipher.getInstance("AES");
		SecretKeySpec k = new SecretKeySpec(key,"AES");
		cipher.init(Cipher.DECRYPT_MODE, k);
		byte[] DecryptedData = cipher.doFinal(encryptedMessage);
		String message = new String(DecryptedData, StandardCharsets.UTF_8);
		System.out.println("El mensaje era: ");
		System.out.println(message);
		return message;
		
	}

	private byte[] generatedSequenceOfBytes() throws Exception {
		StringBuilder randomkey = new StringBuilder();
		for (int i = 0;i < KEYSIZE;i++){
			randomkey.append(Integer.parseInt(Double.toString((Math.random()+0.1)*1000).substring(0,2)));
		}
		return randomkey.toString().getBytes("UTF-8");
	}
}
