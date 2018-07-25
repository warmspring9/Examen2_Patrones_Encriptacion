package com.cenfotec.encrypt.application;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import com.cenfotec.encrypt.manager.EncryptFactory;
import com.cenfotec.encrypt.manager.EncryptionMethod;
import com.cenfotec.encrypt.manager.EncryptionType;

public class EncryptionApplication {

	private static BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	private static EncryptionMethod encryptManager;
	
	public static void main(String[] args) throws Exception {
		EncryptionType type;
		int option = 0;
		
		do {
			do {
				System.out.println("1.Symetric");
				System.out.println("2.Asymetric");
				System.out.println("3.NOT IMPLEMENTED");
				type = getType(Integer.parseInt(br.readLine()));
			} while (type==null);
			System.out.println("1.Create key");
			System.out.println("2.Encript Message");
			System.out.println("3.Decrypt Message");
			System.out.println("4.Exit ");
			option = Integer.parseInt(br.readLine());
			if (option >= 1 && option <= 3){
				executeAction(option,type);
			}
		} while (option != 4);
		
	}
	
	private static EncryptionType getType(int pOption) {
		switch (pOption) {
		case 1: return EncryptionType.SYMETRIC;
		case 2: return EncryptionType.ASYMETRIC;
		case 3: return null;
		}
		return null;
	}

	private static void executeAction(int option, EncryptionType type) throws Exception {
		encryptManager = EncryptFactory.getManager(type);
		if (option == 1){ 
			System.out.println("Key name: ");
			String name = br.readLine();
			encryptManager.createKey(name);
		}
		if (option == 2){
			System.out.println("Key name: ");
			String name = br.readLine();
			System.out.println("Message name: ");
			String messageName = br.readLine();
			System.out.println("Message: ");
			String message = br.readLine();
			encryptManager.encryptMessage(messageName,message,name);		
		}
		if (option == 3){
			System.out.println("Key name: ");
			String keyName = br.readLine();
			System.out.println("Message name: ");
			String messageName = br.readLine();
			encryptManager.decryptMessage(messageName, keyName);			
		}
	}

}
