package it.eng.tz.agid.spid.sael.saml.spid.utils;

public enum SpidAggregatorEntityTypeEnum {
	AGGREGATOR("spid:aggregator"),
	AGGREGATED("spid:aggregated");
	private String entityType;
	private SpidAggregatorEntityTypeEnum(String entityType) {
		this.entityType = entityType;
	}
	public String getEntityType() {
		return entityType;
	}
}
