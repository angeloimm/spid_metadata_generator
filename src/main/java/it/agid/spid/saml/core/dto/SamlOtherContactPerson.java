package it.agid.spid.saml.core.dto;

import java.io.Serializable;

public class SamlOtherContactPerson implements Serializable {

	private static final long serialVersionUID = 7009675469031385512L;
	private boolean spPubblico;
	private String ipaCode;
	private String vatNumber;
	private String fiscalCode;
	private String emailAddress;
	private String telephoneNumber;
	private String companyName;
	public boolean isSpPubblico() {
		return spPubblico;
	}
	public void setSpPubblico(boolean spPubblico) {
		this.spPubblico = spPubblico;
	}
	public String getIpaCode() {
		return ipaCode;
	}
	public void setIpaCode(String ipaCode) {
		this.ipaCode = ipaCode;
	}
	public String getVatNumber() {
		return vatNumber;
	}
	public void setVatNumber(String vatNumber) {
		this.vatNumber = vatNumber;
	}
	public String getFiscalCode() {
		return fiscalCode;
	}
	public void setFiscalCode(String fiscalCode) {
		this.fiscalCode = fiscalCode;
	}
	public String getEmailAddress() {
		return emailAddress;
	}
	public void setEmailAddress(String emailAddress) {
		this.emailAddress = emailAddress;
	}
	public String getTelephoneNumber() {
		return telephoneNumber;
	}
	public void setTelephoneNumber(String telephoneNumber) {
		this.telephoneNumber = telephoneNumber;
	}
	public String getCompanyName() {
		return companyName;
	}
	public void setCompanyName(String companyName) {
		this.companyName = companyName;
	}
	@Override
	public String toString() {
		return "SamlOtherContactPerson [spPubblico=" + spPubblico + ", ipaCode=" + ipaCode + ", vatNumber=" + vatNumber
				+ ", fiscalCode=" + fiscalCode + ", emailAddress=" + emailAddress + ", telephoneNumber="
				+ telephoneNumber + ", companyName=" + companyName + "]";
	}
	
}
