package it.eng.tz.agid.spid.sael.saml.core.dto;

import java.io.Serializable;

public class SamlFpaFiscaleIva implements Serializable {

	private static final long serialVersionUID = 4187577171160575834L;
	private String idPaese;
	private String idCodice;
	public String getIdPaese() {
		return idPaese;
	}
	public void setIdPaese(String idPaese) {
		this.idPaese = idPaese;
	}
	public String getIdCodice() {
		return idCodice;
	}
	public void setIdCodice(String idCodice) {
		this.idCodice = idCodice;
	}
	@Override
	public String toString() {
		return "SamlFpaFiscaleIva [idPaese=" + idPaese + ", idCodice=" + idCodice + "]";
	}
	
}
