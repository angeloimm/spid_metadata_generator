package it.agid.spid.saml.core.dto;

import java.io.Serializable;

public class SamlOrganizationDto implements Serializable{
	
	private static final long serialVersionUID = -4993530789366729260L;
	private String organizationDisplayName;
	private String organizationName;
	private String organizationUrl;
	public String getOrganizationDisplayName() {
		return organizationDisplayName;
	}
	public void setOrganizationDisplayName(String organizationDisplayName) {
		this.organizationDisplayName = organizationDisplayName;
	}
	public String getOrganizationName() {
		return organizationName;
	}
	public void setOrganizationName(String organizationName) {
		this.organizationName = organizationName;
	}
	public String getOrganizationUrl() {
		return organizationUrl;
	}
	public void setOrganizationUrl(String organizationUrl) {
		this.organizationUrl = organizationUrl;
	}
	@Override
	public String toString() {
		return "SamlOrganizationDto [organizationDisplayName=" + organizationDisplayName + ", organizationName="
				+ organizationName + ", organizationUrl=" + organizationUrl + "]";
	}
	
}
