package it.eng.tz.agid.spid.sael.saml.core.dto;

import java.io.Serializable;

public class SamlFpaDatiAnagraficiConcessionario implements Serializable {

	private static final long serialVersionUID = -2156889251447206389L;
	private SamlFpaFiscaleIva fiscaleIva;
	private String denominazione;
	public SamlFpaFiscaleIva getFiscaleIva() {
		return fiscaleIva;
	}
	public void setFiscaleIva(SamlFpaFiscaleIva fiscaleIva) {
		this.fiscaleIva = fiscaleIva;
	}
	public String getDenominazione() {
		return denominazione;
	}
	public void setDenominazione(String denominazione) {
		this.denominazione = denominazione;
	}
	@Override
	public String toString() {
		return "SamlFpaDatiAnagraficiConcessionario [fiscaleIva=" + fiscaleIva + ", denominazione=" + denominazione
				+ "]";
	}
}
