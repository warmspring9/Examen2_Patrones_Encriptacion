package com.cenfotec.encrypt.manager.test;

import static org.junit.Assert.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Before;
import org.junit.Test;

import com.cenfotec.encrypt.manager.AlternativeManager;
import com.cenfotec.encrypt.manager.AsymetricManager;
import com.cenfotec.encrypt.manager.SymetricManager;

public class EncriptionTest {

	SymetricManager manager;
	AsymetricManager manager2;
	AlternativeManager manager3;
	
	@Before
	public void init() throws Exception {
		manager = new SymetricManager();
		manager2 = new AsymetricManager();
		manager3 = new AlternativeManager();
	}
	
	@Test
	public void SymetricEncryptTest() throws InvalidKeyException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		assertEquals("dIiGUDnNozL+gcgwbS64sw==",manager.encryptMessage("test1", "la vida es dura", "llave"));
	}
	
	@Test
	public void SymetricDecryptTest() throws Exception {
		assertEquals("la vida es dura",manager.decryptMessage("test1", "llave"));
	}
	
	@Test
	public void AsymetricEncryptTest() throws InvalidKeyException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		manager2.encryptMessage("test2", "la vida es dura", "llavita");
	}
	
	@Test
	public void AsymetricDecryptTest() throws Exception {
		assertEquals("la vida es dura",manager2.decryptMessage("test2", "llavita"));
	}
	
	@Test
	public void SymetricDESEncryptTest() throws InvalidKeyException, FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		assertEquals("mH337VFfKJjEc2BCDbNOZw==",manager3.encryptMessage("test3", "la vida es dura", "keyThing"));
	}
	
	@Test
	public void SymetricDESDecryptTest() throws Exception {
		assertEquals("la vida es dura",manager3.decryptMessage("test3", "keyThing"));
	}
}
