package it.eng.tz.agid.spid.sael.saml.core.utils;

public abstract class StringUtil {
	
	public static boolean isEmptyString( String value ) {
		
		return value == null || value.trim().equals("");
	}
}
