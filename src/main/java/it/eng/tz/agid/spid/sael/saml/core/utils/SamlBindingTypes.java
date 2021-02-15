package it.eng.tz.agid.spid.sael.saml.core.utils;

public enum SamlBindingTypes {
	POST("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
	REDIRECT("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
	
	private String bindingType;
	private SamlBindingTypes(String bindingType) {
		this.bindingType = bindingType;
	}
	public String getBindingType() {
		return bindingType;
	}
}
