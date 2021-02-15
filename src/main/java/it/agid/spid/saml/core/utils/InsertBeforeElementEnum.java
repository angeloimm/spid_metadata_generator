package it.agid.spid.saml.core.utils;

public enum InsertBeforeElementEnum {
	SP_TAG("*", "SPSSODescriptor"),
	IDP_TAG("*", "IDPSSODescriptor");
	
	private String nameSpace;
	private String elementName;
	private InsertBeforeElementEnum(String nameSpace, String elementName) {
		this.nameSpace = nameSpace;
		this.elementName = elementName;
	}
	public String getNameSpace() {
		return nameSpace;
	}
	public String getElementName() {
		return elementName;
	}
}
