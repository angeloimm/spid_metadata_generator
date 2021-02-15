package it.agid.spid.saml.spid.utils;

import java.util.ArrayList;
import java.util.List;

import it.agid.spid.saml.core.dto.SamlAttributeDto;
import it.agid.spid.saml.core.dto.SamlAttributesConsumingServiceDto;

public abstract class AgidUtils {
	
	public static List<SamlAttributesConsumingServiceDto> agidSpidEidasAttributes(){
		List<SamlAttributesConsumingServiceDto> acss = new ArrayList<SamlAttributesConsumingServiceDto>(5);
		List<SamlAttributeDto> spidAttributesMinimo = new ArrayList<SamlAttributeDto>();
		spidAttributesMinimo.add(new SamlAttributeDto("SPID Code", "spidCode"));
		spidAttributesMinimo.add(new SamlAttributeDto("Nome", "name"));
		spidAttributesMinimo.add(new SamlAttributeDto("Cognome", "familyName"));
		spidAttributesMinimo.add(new SamlAttributeDto("Data di nascita", "dateOfBirth"));
		spidAttributesMinimo.add(new SamlAttributeDto("Codice Fiscale", "fiscalNumber"));
		spidAttributesMinimo.add(new SamlAttributeDto("Indirizzo di posta elettronica", "email"));
		SamlAttributesConsumingServiceDto spidAcsMinimo = new SamlAttributesConsumingServiceDto(0, "minimo", "it", spidAttributesMinimo);
		acss.add(spidAcsMinimo);				
		List<SamlAttributeDto> spidAttributesEsteso = new ArrayList<SamlAttributeDto>();
		spidAttributesEsteso.add(new SamlAttributeDto("SPID Code", "spidCode"));
		spidAttributesEsteso.add(new SamlAttributeDto("Nome", "name"));
		spidAttributesEsteso.add(new SamlAttributeDto("Cognome", "familyName"));
		spidAttributesEsteso.add(new SamlAttributeDto("Luogo di nascita", "placeOfBirth"));
		spidAttributesEsteso.add(new SamlAttributeDto("Provincia di nascita", "countyOfBirth"));
		spidAttributesEsteso.add(new SamlAttributeDto("Data di nascita", "dateOfBirth"));
		spidAttributesEsteso.add(new SamlAttributeDto("Sesso", "gender"));
		spidAttributesEsteso.add(new SamlAttributeDto("Codice Fiscale", "fiscalNumber"));
		spidAttributesEsteso.add(new SamlAttributeDto("Documento di identità", "idCard"));
		spidAttributesEsteso.add(new SamlAttributeDto("Numero di telefono mobile", "mobilePhone"));
		spidAttributesEsteso.add(new SamlAttributeDto("Indirizzo di posta elettronica", "email"));
		spidAttributesEsteso.add(new SamlAttributeDto("Domicilio fisico", "address"));
		spidAttributesEsteso.add(new SamlAttributeDto("Data di scadenza identità", "expirationDate"));
		spidAttributesEsteso.add(new SamlAttributeDto("Domicilio digitale", "digitalAddress"));
		SamlAttributesConsumingServiceDto spidAcsEsteso = new SamlAttributesConsumingServiceDto(1, "esteso", "it", spidAttributesEsteso);
		acss.add(spidAcsEsteso);		
		List<SamlAttributeDto> spidAttributes = new ArrayList<SamlAttributeDto>();
		spidAttributes.add(new SamlAttributeDto("SPID Code", "spidCode"));
		spidAttributes.add(new SamlAttributeDto("Nome", "name"));
		spidAttributes.add(new SamlAttributeDto("Cognome", "familyName"));
		spidAttributes.add(new SamlAttributeDto("Luogo di nascita", "placeOfBirth"));
		spidAttributes.add(new SamlAttributeDto("Provincia di nascita", "countyOfBirth"));
		spidAttributes.add(new SamlAttributeDto("Data di nascita", "dateOfBirth"));
		spidAttributes.add(new SamlAttributeDto("Sesso", "gender"));
		spidAttributes.add(new SamlAttributeDto("Ragione o denominazione sociale", "companyName"));
		spidAttributes.add(new SamlAttributeDto("Sede legale", "registeredOffice"));
		spidAttributes.add(new SamlAttributeDto("Codice Fiscale", "fiscalNumber"));
		spidAttributes.add(new SamlAttributeDto("Partita IVA", "ivaCode"));
		spidAttributes.add(new SamlAttributeDto("Documento di identità", "idCard"));
		spidAttributes.add(new SamlAttributeDto("Numero di telefono mobile", "mobilePhone"));
		spidAttributes.add(new SamlAttributeDto("Indirizzo di posta elettronica", "email"));
		spidAttributes.add(new SamlAttributeDto("Domicilio fisico", "address"));
		spidAttributes.add(new SamlAttributeDto("Data di scadenza identità", "expirationDate"));
		spidAttributes.add(new SamlAttributeDto("Domicilio digitale", "digitalAddress"));
		SamlAttributesConsumingServiceDto spidAcs = new SamlAttributesConsumingServiceDto(2, "completo", "it", spidAttributes);
		acss.add(spidAcs);

		List<SamlAttributeDto> eidasAttributesMinimum = new ArrayList<SamlAttributeDto>();
		eidasAttributesMinimum.add(new SamlAttributeDto("", "spidCode"));
		eidasAttributesMinimum.add(new SamlAttributeDto("", "name"));
		eidasAttributesMinimum.add(new SamlAttributeDto("", "familyName"));
		eidasAttributesMinimum.add(new SamlAttributeDto("", "dateOfBirth"));
		SamlAttributesConsumingServiceDto eidasMin = new SamlAttributesConsumingServiceDto(99, "eIDAS Natural Person Minimum Attribute Set", "it", eidasAttributesMinimum);
		acss.add(eidasMin);

		List<SamlAttributeDto> eidasAttributesFull = new ArrayList<SamlAttributeDto>();
		eidasAttributesFull.add(new SamlAttributeDto("", "spidCode"));
		eidasAttributesFull.add(new SamlAttributeDto("", "name"));
		eidasAttributesFull.add(new SamlAttributeDto("", "familyName"));
		eidasAttributesFull.add(new SamlAttributeDto("", "dateOfBirth"));
		eidasAttributesFull.add(new SamlAttributeDto("", "placeOfBirth"));
		eidasAttributesFull.add(new SamlAttributeDto("", "address"));
		eidasAttributesFull.add(new SamlAttributeDto("", "gender"));
		SamlAttributesConsumingServiceDto eidasFull = new SamlAttributesConsumingServiceDto(100, "eIDAS Natural Person Full Attribute Set", "it", eidasAttributesFull);
		acss.add(eidasFull);
		return acss;
	}
}
