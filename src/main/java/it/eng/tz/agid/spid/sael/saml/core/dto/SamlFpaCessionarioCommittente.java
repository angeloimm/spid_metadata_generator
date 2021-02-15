package it.eng.tz.agid.spid.sael.saml.core.dto;

import java.io.Serializable;

public class SamlFpaCessionarioCommittente implements Serializable {

	private static final long serialVersionUID = -4904103271544708177L;
	private SamlFpaDatiAnagraficiConcessionario datiAnagrafici;
	private SamlFpaSede sede;
	private String company;
	private String mail;
	private String telephoneNumber;
	public SamlFpaDatiAnagraficiConcessionario getDatiAnagrafici() {
		return datiAnagrafici;
	}
	public void setDatiAnagrafici(SamlFpaDatiAnagraficiConcessionario datiAnagrafici) {
		this.datiAnagrafici = datiAnagrafici;
	}
	public SamlFpaSede getSede() {
		return sede;
	}
	public void setSede(SamlFpaSede sede) {
		this.sede = sede;
	}
	public String getCompany() {
		return company;
	}
	public void setCompany(String company) {
		this.company = company;
	}
	public String getMail() {
		return mail;
	}
	public void setMail(String mail) {
		this.mail = mail;
	}
	public String getTelephoneNumber() {
		return telephoneNumber;
	}
	public void setTelephoneNumber(String telephoneNumber) {
		this.telephoneNumber = telephoneNumber;
	}
	@Override
	public String toString() {
		return "SamlFpaCessionarioCommittente [datiAnagrafici=" + datiAnagrafici + ", sede=" + sede + ", company="
				+ company + ", mail=" + mail + ", telephoneNumber=" + telephoneNumber + "]";
	}

}
