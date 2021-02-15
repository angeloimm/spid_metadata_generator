package it.eng.tz.agid.spid.sael.saml.spid.utils;

public enum SoggettoAggregatoreConvention {
	AGGREGATORE_FULL_SERVIZI_PUBBLICI("pub-ag-full", "PublicServicesFullAggregator"),
	AGGREGATORE_LIGHT_SERVIZI_PUBBLICI("pub-ag-lite", "PublicServicesLightAggregator"),
	AGGREGATORE_FULL_SERVIZI_PRIVATI("pri-ag-full", "PrivateServicesFullAggregator"),
	AGGREGATORE_LIGHT_SERVIZI_PRIVATI("pri-ag-lite", "PrivateServicesLightAggregator"),
	GESTORE_FULL_SERVIZI_PUBBLICI("pub-op-full", "PublicServicesFullOperator"),
	GESTORE_LIGHT_SERVIZI_PUBBLICI("pub-op-lite", "PublicServicesLightOperator");
	
	private String codiceAttivita;
	private String metadataTagName;
	private SoggettoAggregatoreConvention(String codiceAttivita, String metadataTagName) {
		this.codiceAttivita = codiceAttivita;
		this.metadataTagName = metadataTagName;
	}
	public String getCodiceAttivita() {
		return codiceAttivita;
	}
	public String getMetadataTagName() {
		return metadataTagName;
	}
	
}
