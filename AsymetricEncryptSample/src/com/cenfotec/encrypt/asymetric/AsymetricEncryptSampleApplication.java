package com.cenfotec.encrypt.asymetric;


import com.cenfotec.encrypt.asymetric.asimetricManager.EncryptManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;


public class AsymetricEncryptSampleApplication {
	
	private static BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	private static EncryptManager encryptManager = new EncryptManager();
	
	
	public static void main(String[] args) throws Exception {
		int option = 0;
		do {
    		System.out.println("1.Create key");
        	System.out.println("2.Encript Message");
        	System.out.println("3.Decrypt Message");
        	System.out.println("4.Exit ");
        	option = Integer.parseInt(br.readLine());
        	if (option >= 1 && option <= 3){
        		executeAction(option);
        	}
    	} while (option != 4);

    	
    }

	private static void executeAction(int option) throws Exception {
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
