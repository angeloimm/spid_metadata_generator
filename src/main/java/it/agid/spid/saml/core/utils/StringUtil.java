package it.agid.spid.saml.core.utils;

public abstract class StringUtil {
	
	public static boolean isEmptyString( String value ) {
		
		return value == null || value.trim().equals("");
	}
}
