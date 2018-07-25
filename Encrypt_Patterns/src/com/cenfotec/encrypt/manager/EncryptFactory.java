package com.cenfotec.encrypt.manager;

public class EncryptFactory {
	
	public static EncryptionMethod getManager(EncryptionType pType) {
		switch(pType) {
		case ASYMETRIC: return new AsymetricManager();
		case SYMETRIC: return new SymetricManager();
		default: return null;
		}
	}
}
