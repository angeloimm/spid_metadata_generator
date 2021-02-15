package it.agid.spid.saml.core.dto;
import java.io.Serializable;
import java.util.List;

public class SamlAttributesConsumingServiceDto implements Serializable {

	private static final long serialVersionUID = 3537088671257789084L;
	private Integer index;
	private String serviceName;
	private String serviceNameLang;
	private List<SamlAttributeDto> attrs;
	
	public SamlAttributesConsumingServiceDto() {
		super();
	}
	public SamlAttributesConsumingServiceDto(Integer index, String serviceName, String serviceNameLang,
			List<SamlAttributeDto> attrs) {
		super();
		this.index = index;
		this.serviceName = serviceName;
		this.serviceNameLang = serviceNameLang;
		this.attrs = attrs;
	}
	public Integer getIndex() {
		return index;
	}
	public void setIndex(Integer index) {
		this.index = index;
	}
	public String getServiceName() {
		return serviceName;
	}
	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}
	public String getServiceNameLang() {
		return serviceNameLang;
	}
	public void setServiceNameLang(String serviceNameLang) {
		this.serviceNameLang = serviceNameLang;
	}
	public List<SamlAttributeDto> getAttrs() {
		return attrs;
	}
	public void setAttrs(List<SamlAttributeDto> attrs) {
		this.attrs = attrs;
	}
	
}
