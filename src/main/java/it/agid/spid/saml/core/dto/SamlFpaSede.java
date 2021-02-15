package it.agid.spid.saml.core.dto;

import java.io.Serializable;

public class SamlFpaSede implements Serializable {

	private static final long serialVersionUID = 459837856264092055L;
	private String indrizzo;
	private String numeroCivico;
	private String cap;
	private String comune;
	private String provincia;
	private String nazione;
	public String getIndrizzo() {
		return indrizzo;
	}
	public void setIndrizzo(String indrizzo) {
		this.indrizzo = indrizzo;
	}
	public String getNumeroCivico() {
		return numeroCivico;
	}
	public void setNumeroCivico(String numeroCivico) {
		this.numeroCivico = numeroCivico;
	}
	public String getCap() {
		return cap;
	}
	public void setCap(String cap) {
		this.cap = cap;
	}
	public String getComune() {
		return comune;
	}
	public void setComune(String comune) {
		this.comune = comune;
	}
	public String getProvincia() {
		return provincia;
	}
	public void setProvincia(String provincia) {
		this.provincia = provincia;
	}
	public String getNazione() {
		return nazione;
	}
	public void setNazione(String nazione) {
		this.nazione = nazione;
	}
	@Override
	public String toString() {
		return "SamlFpaSede [indrizzo=" + indrizzo + ", numeroCivico=" + numeroCivico + ", cap=" + cap + ", comune="
				+ comune + ", provincia=" + provincia + ", nazione=" + nazione + "]";
	}
	
}
