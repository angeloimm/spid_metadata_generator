package it.eng.tz.agid.spid.sael.saml.core.utils;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.eng.tz.agid.spid.sael.saml.core.dto.SamlAttributeDto;
import it.eng.tz.agid.spid.sael.saml.core.dto.SamlAttributesConsumingServiceDto;
import it.eng.tz.agid.spid.sael.saml.spid.exception.SpidCheckerException;

public abstract class SpidControlChecker {
	public static final String BASE_SPID_AUTHN_CONTEXT_CLAS_REF = "https://www.spid.gov.it/SpidL";
	private static final Logger logger = LoggerFactory.getLogger(SpidControlChecker.class.getName());
	/**
	 * Controlla se la saml response {@link Response} è compliant ai controlli SPID definiti nello spid validator
	 * @param samlResponse -la {@link Response} da controllare
	 * @param credentials -il {@link List} di {@link Credential} da utilizzare per il controllo della firma 
	 * @param tolleranceTimeMillisecond il tempo di tolleranza in millisecondi. 
	 * 									Tutte le response che hanno un tempo di arrivo che rientra nel 
	 * 									range + o - il tempo di tolleranza in millisecondi sono da considerarsi valide.
	 * 									In genere sono OK temi di tolleranza di 3 minuti (180*1000 millisecondi)
	 * @param idpDestinationUrl - Destination URL verso cui tutte le SAML Response devono puntare ed è coindidente con AssertionConsumerServiceURL della SAML Request inviata a SPID.
	 * @param spidIdpEntityId -IDP Entity ID
	 * @param spitEnteAggregatoMetadata - {@link EntityDescriptor} contentente le informazioni del metadata dell'ente aggregato
	 * @param attributiRichiesti -Gli attributi richiesti dall'SP dell'ente
	 * @param keyPair il {@link KeyPair} usato per decriptare le assertion
	 * @param spLivelloAutenticazioneSpid il livello di autenticazione SPID richiesto da SP
	 * @throws SpidCheckerException sollevata se uno dei controlli spid fallisce
	 */
	public static void verifySamlResponseSpidCompliance( 	Response samlResponse, 
			List<Credential> credentials, 
			int tolleranceTimeMillisecond, 
			String idpDestinationUrl, 
			String spidIdpEntityId,
			EntityDescriptor spitEnteAggregatoMetadata,
			SamlAttributesConsumingServiceDto attributiRichiesti,
			KeyPair keyPair,
			int spLivelloAutenticazioneSpid) throws SpidCheckerException {
		//Controllo id response
		String responseId = samlResponse.getID();
		if( StringUtil.isEmptyString(responseId) ) {
			throw new SpidCheckerException("SAML Response ID non presente o non valorizzato ["+responseId+"] SAML Response non valida");
		}
		//Controllo version
		SAMLVersion version = samlResponse.getVersion();
		if( !version.equals(SAMLVersion.VERSION_20) ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" SAML Version ["+version+"] differente da ["+SAMLVersion.VERSION_20+"] SAML Response non valida");
		}
		//Controllo firma saml response e assertion
		//Firma saml response
		boolean validSign = OpenSAMLUtils.isSignatureValid(samlResponse.getSignature(), credentials);
		if( !validSign ) {
			throw new SpidCheckerException("Firma SAML Response non valida");
		}
		//Controllo su element status
		checkSamlResponseStatus( samlResponse );
		//Firma assertion
		List<Assertion> assertions = samlResponse.getAssertions();
		if( assertions == null || assertions.isEmpty() ) {
			assertions = decriptAssertion(samlResponse.getEncryptedAssertions(), keyPair);
		}

		//Controllo assertion
		checkSamlResponseAssertions( samlResponse, assertions, credentials, tolleranceTimeMillisecond, idpDestinationUrl, spidIdpEntityId, spitEnteAggregatoMetadata, attributiRichiesti.getAttrs(), spLivelloAutenticazioneSpid );
		//Controllo response issue instant
		DateTime responseIssueInstant = samlResponse.getIssueInstant();
		checkSamlResponseIssueInstant( responseIssueInstant, assertions, tolleranceTimeMillisecond );
		//Controllo sulla destination
		checkSamlResponseDestination( samlResponse, idpDestinationUrl );

		//Controlli sullo issuer
		checkSamlResponseIssuer( samlResponse, spidIdpEntityId );
	}
	/**
	 * Effettuo i controlli sulle assertion
	 * @param samlResponse la {@link Response} su cui è necessario effettuare i controlli 
	 * @param assertions -il {@link List} di {@link Assertion} da controllare
	 * @param credentials -il {@link List} di {@link Credential} con cui verificare la firma delle assertion
	 * @param tolleranceTimeMillisecond -il tempo di tolleranza in millisecondi
	 * @param idpDestinationUrl - Destination URL verso chui tutte le SAML Response devono puntare ed è coindidente con AssertionConsumerServiceURL della SAML Request inviata a SPID.
	 * @param spidIdpEntityId -IDP Entity ID
	 * @param spitEnteAggregatoMetadata - {@link EntityDescriptor} rappresentante il metadata dell'ente aggregato
	 * @param attributiRichiesti -Il {@link List} di {@link SamlAttributesConsumingServiceDto} richiesti
	 * @param spLivelloAutenticazioneSpid -Il livello di autenticazione SPID richiesto dall'SP dell'ente
	 * @throws SpidCheckerException -sollevata se qualche controllo fallisce
	 */
	private static void checkSamlResponseAssertions( 	Response samlResponse, 
			List<Assertion> assertions, 
			List<Credential> credentials, 
			int tolleranceTimeMillisecond, 
			String idpDestinationUrl, 
			String spidIdpEntityId,
			EntityDescriptor spitEnteAggregatoMetadata,
			List<SamlAttributeDto> attributiRichiesti,
			int spLivelloAutenticazioneSpid) throws SpidCheckerException {
		if( assertions == null || assertions.isEmpty() ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" nessun tag assertion trovato SAML Response non valida");
		}

		for (Assertion assertion : assertions) {
			String assertionId = assertion.getID();
			if( StringUtil.isEmptyString(assertionId) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" assertion ID non presente o vuoto SAML Response non valida");
			}
			boolean validAssSign = OpenSAMLUtils.isSignatureValid(assertion.getSignature(), credentials);
			if( !validAssSign ) {

				throw new SpidCheckerException("SAML Response ID ["+samlResponse.getID()+"] Firma Assertion "+assertion.getID()+" non verificata SAML Response non valida");
			}

			SAMLVersion assertionVersion = assertion.getVersion();
			if( !assertionVersion.equals(SAMLVersion.VERSION_20) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" assertion ID ["+assertionId+"] SAML Version ["+assertionVersion+"] differente da ["+SAMLVersion.VERSION_20+"] SAML Response non valida");
			}
			DateTime assertionIssueInstant = null;
			try {
				assertionIssueInstant = assertion.getIssueInstant();
			}catch (Exception e) {
				logger.error("Errore nel recupero di assertionIssueInstant", e);
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" assertion ID ["+assertionId+"] errore nel recupero dello issue instant SAML Response non valida");
			}
			if( assertionIssueInstant == null ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" assertion ID ["+assertionId+"] issue instant non presente SAML Response non valida");
			}
			List<AuthnStatement> statemens = assertion.getAuthnStatements();
			for (AuthnStatement statement : statemens) {
				DateTime requestTime = statement.getAuthnInstant();
				DateTime requestTimeMinus = requestTime.minusMillis(tolleranceTimeMillisecond);
				if( assertionIssueInstant.isBefore(requestTimeMinus) ) {
					throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Assertion Issue Instant ["+assertionIssueInstant+"] Request issuer time ["+requestTime+"] SAML Response non valida. Issue Instant della SAML Assertion precedente a quello della request");
				}
				DateTime requestTimePlus = requestTime.plusMillis(tolleranceTimeMillisecond);
				if( assertionIssueInstant.isAfter(requestTimePlus) ) {
					throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Assertion Issue Instant ["+assertionIssueInstant+"] Request issuer time ["+requestTime+"] SAML Response non valida. Issue Instant della SAML Assertion successivo a quello della request");
				}
			}

			Subject assertionSubject = assertion.getSubject();
			if( assertionSubject == null || !assertionSubject.hasChildren() ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Subject nullo SAML Response non valida.");
			}
			NameID subjectNameId = assertionSubject.getNameID();
			if( subjectNameId == null ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Subject Name ID nullo SAML Response non valida.");
			}
			String subjectNameIdFormat = subjectNameId.getFormat();
			if( StringUtil.isEmptyString(subjectNameIdFormat) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Subject Name ID Format nullo o vuoto ["+subjectNameIdFormat+"] SAML Response non valida.");
			}
			if( !NameIDType.TRANSIENT.equals(subjectNameIdFormat) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Subject Name ID Format ["+subjectNameIdFormat+"] diverso da "+NameIDType.TRANSIENT+" SAML Response non valida.");
			}
			String subjectNameIdNameQualifier = subjectNameId.getNameQualifier();
			if( StringUtil.isEmptyString(subjectNameIdNameQualifier) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Subject Name ID Qualifier nullo o vuoto ["+subjectNameIdNameQualifier+"] SAML Response non valida.");
			}
			List<SubjectConfirmation> subjectConfirmations = assertionSubject.getSubjectConfirmations();
			if( subjectConfirmations == null || subjectConfirmations.isEmpty() ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". SubjectConfirmation nullo o vuoto SAML Response non valida.");
			}
			checkSamlResponseSubjectConfirmation(samlResponse, assertion.getID(), subjectConfirmations, idpDestinationUrl, assertion.getConditions());
			Issuer assertionIssuer = assertion.getIssuer();
			if( assertionIssuer == null ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Issuer nullo o vuoto SAML Response non valida.");
			}
			String assertionIssuerValue = assertionIssuer.getValue();
			if( StringUtil.isEmptyString(assertionIssuerValue) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Valore Issuer nullo o vuoto "+assertionIssuerValue+" SAML Response non valida.");
			}else if( !spidIdpEntityId.equals(assertionIssuerValue) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Valore Issuer "+assertionIssuerValue+" differente da IDP Entity ID "+spidIdpEntityId+" SAML Response non valida.");
			}
			String assertionIssuerFormat = assertionIssuer.getFormat();
			if( StringUtil.isEmptyString(assertionIssuerFormat) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Attributo Format Issuer nullo o vuoto "+assertionIssuerFormat+" SAML Response non valida.");
			}else if( !NameIDType.ENTITY.equals(assertionIssuerFormat) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Attributo Format Issuer ["+assertionIssuerFormat+"] diverso da "+NameIDType.ENTITY+" SAML Response non valida.");
			}
			//check condtions
			checkSamlResponseAssertionConditions( samlResponse, assertion, spitEnteAggregatoMetadata, attributiRichiesti, spLivelloAutenticazioneSpid);
		}
	}
	private static void checkSamlResponseAssertionConditions(Response samlResponse, Assertion assertion, EntityDescriptor spitEnteAggregatoMetadata,List<SamlAttributeDto> attributiRichiesti, int spLivelloAutenticazioneSpid) throws SpidCheckerException {
		Conditions conditions = assertion.getConditions();
		if( conditions == null ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions nulle SAML Response non valida.");
		}
		DateTime condNotBefore = null;
		try {
			condNotBefore = conditions.getNotBefore();
		} catch (Exception e) {
			logger.error("Errore nel recupero di condNotBefore", e);
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions attributo NotBefore formato non corretto SAML Response non valida.");
		}
		if( condNotBefore == null ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions attributo NotBefore non valorizzato o null SAML Response non valida.");
		}
		if( condNotBefore.isAfter(samlResponse.getIssueInstant()) ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions attributo NotBefore "+condNotBefore+" saml response issue instant "+samlResponse.getIssueInstant()+" SAML Response non valida.");
		}
		DateTime condNotOnOrAfter = null;
		try {
			condNotOnOrAfter = conditions.getNotOnOrAfter();
		} catch (Exception e) {
			logger.error("Errore nel recupero di condNotOnOrAfter", e);
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions attributo NotOnOrAfter formato non corretto SAML Response non valida.");
		}
		if( condNotOnOrAfter == null ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions attributo NotOnOrAfter non valorizzato o null SAML Response non valida.");
		}
		if( condNotOnOrAfter.isBefore(samlResponse.getIssueInstant()) ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions attributo NotOnOrAfter "+condNotOnOrAfter+" saml response issue instant "+samlResponse.getIssueInstant()+" SAML Response non valida.");
		}
		List<AudienceRestriction> condAudienceRestrictions = conditions.getAudienceRestrictions();
		if( condAudienceRestrictions == null || condAudienceRestrictions.isEmpty() ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Contitions audience restrictions non valorizzato o null SAML Response non valida.");
		}

		checkSamlResponseAssertionConditionsAudiendeRestriction( samlResponse, assertion, condAudienceRestrictions, spitEnteAggregatoMetadata );
		checkSamlResponseAssertionAuthStatement( samlResponse, assertion, assertion.getAuthnStatements(), spitEnteAggregatoMetadata, spLivelloAutenticazioneSpid );
		checkSamlResponseAssertionAttributeStatement( samlResponse, assertion, assertion.getAttributeStatements(), spitEnteAggregatoMetadata, attributiRichiesti );
	}
	private static void checkSamlResponseAssertionAttributeStatement(	Response samlResponse, 
			Assertion assertion,
			List<AttributeStatement> attributeStatements, 
			EntityDescriptor spitEnteAggregatoMetadata,
			List<SamlAttributeDto> attributiRichiesti) throws SpidCheckerException {
		if( attributeStatements == null || attributeStatements.isEmpty() ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". AttributeStatemente non valorizzato o null SAML Response non valida.");
		}
		for (AttributeStatement attributeStatement : attributeStatements) {
			List<Attribute> attributes = attributeStatement.getAttributes();
			if( attributes == null || attributes.isEmpty() ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Attribute non valorizzato o null SAML Response non valida.");
			}
			if( attributes.size() != attributiRichiesti.size() ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Richiesti "+attributiRichiesti.size()+" attributi al provider SPID. Ricevuti "+attributes.size()+" attributi SAML Response non valida.");
			}
			List<String> nomiAttributiRichiesti = new ArrayList<>(attributiRichiesti.size());
			attributiRichiesti.forEach(attr->{
				nomiAttributiRichiesti.add(attr.getName());
			});
			for (Attribute attribute : attributes) {

				if( attribute == null || !attribute.hasChildren() ) {
					throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Attribute null o non specificato SAML Response non valida.");
				}
				String attrNameFormat = attribute.getNameFormat();
				if( StringUtil.isEmptyString(attrNameFormat) ) {
					if( logger.isWarnEnabled() ) {
						logger.warn	("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Attribute name format null o non specificato SAML Response valida.");;
					}

				}
				if( !nomiAttributiRichiesti.contains(attribute.getName()) ) {
					throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Attribute name "+attribute.getName()+" non contenuto nel set di attributi richiesti a SPID "+nomiAttributiRichiesti+" SAML Response non valida.");
				}
			}
		}

	}
	private static void checkSamlResponseAssertionAuthStatement(Response samlResponse, 
			Assertion assertion,
			List<AuthnStatement> authnStatements, 
			EntityDescriptor spitEnteAggregatoMetadata,
			int spLivelloAutenticazioneSpid) throws SpidCheckerException{
		if( authnStatements == null || authnStatements.isEmpty() ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". AuthStatement non valorizzato o null SAML Response non valida.");
		}
		for (AuthnStatement authnStatement : authnStatements) {

			if( authnStatement == null || !authnStatement.hasChildren() ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". AuthStatement non valorizzato o null SAML Response non valida.");
			}
			AuthnContext authCtx = authnStatement.getAuthnContext();
			if( authCtx == null || !authCtx.hasChildren() ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". AuthnContext di AuthStatement non valorizzato o null SAML Response non valida.");
			}
			AuthnContextClassRef authnContextClassRef = authCtx.getAuthnContextClassRef();
			if( authnContextClassRef == null ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". AuthnContextClassRef di AuthnContext di AuthStatement non valorizzato o null SAML Response non valida.");
			}
			String authnContextClassRefValue = authnContextClassRef.getAuthnContextClassRef();
			if( StringUtil.isEmptyString(authnContextClassRefValue) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Value di AuthnContextClassRef di AuthnContext di AuthStatement non valorizzato o null SAML Response non valida.");
			}
			if( !authnContextClassRefValue.equals(BASE_SPID_AUTHN_CONTEXT_CLAS_REF+"1") &&
					!authnContextClassRefValue.equals(BASE_SPID_AUTHN_CONTEXT_CLAS_REF+"2") && 
					!authnContextClassRefValue.equals(BASE_SPID_AUTHN_CONTEXT_CLAS_REF+"3")) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Value di AuthnContextClassRef di AuthnContext di AuthStatement ["+authnContextClassRefValue+"] non previsto SAML Response non valida.");
			}

			int livelloSpid = Integer.parseInt(authnContextClassRefValue.replaceAll(BASE_SPID_AUTHN_CONTEXT_CLAS_REF, ""));
			if( livelloSpid < spLivelloAutenticazioneSpid ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Value di AuthnContextClassRef di AuthnContext di AuthStatement ["+authnContextClassRefValue+"] maggiore di https://www.spid.gov.it/SpidL"+spLivelloAutenticazioneSpid+" SAML Response non valida.");
			}
		}

	}


	/**
	 * Effettua i controlli sulle {@link Conditions} della {@link Assertion} della {@link Response} saml
	 * @param samlResponse -la {@link Response} saml
	 * @param assertion -la {@link Assertion}
	 * @param condAudienceRestrictions il {@link List} di {@link AudienceRestriction}
	 * @param spitEnteAggregatoMetadata {@link EntityDescriptor} rappresentante il metadata dell'ente da creare
	 * @throws SpidCheckerException sollevata se un controllo va male
	 */
	private static void checkSamlResponseAssertionConditionsAudiendeRestriction(Response samlResponse,	Assertion assertion, List<AudienceRestriction> condAudienceRestrictions, EntityDescriptor spitEnteAggregatoMetadata) throws SpidCheckerException {
		for (AudienceRestriction audienceRestriction : condAudienceRestrictions) {
			List<Audience> audiences = audienceRestriction.getAudiences();
			if( audiences == null || audiences.isEmpty() ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Audience non valorizzato o null SAML Response non valida.");
			}
			for (Audience audience : audiences) {
				String audienceValue = audience.getAudienceURI();
				if( StringUtil.isEmptyString(audienceValue) ) {
					throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Audience URI "+audienceValue+" nullo o vuoto SAML Response non valida.");
				}else if( !audienceValue.equals(spitEnteAggregatoMetadata.getEntityID()) ) {
					throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertion.getID()+". Audience URI "+audienceValue+" diverso da entity id di SP "+spitEnteAggregatoMetadata.getEntityID()+" SAML Response non valida.");
				}
			}
		}
	}
	/**
	 * Effettua i controlli sul {@link List} si {@link SubjectConfirmation} contenuti nella {@link Response} saml
	 * @param samlResponse -la {@link Response}
	 * @param assertionId -Id dell'assertion SAML che stiamo controllando
	 * @param subjectConfirmations il {@link List} di {@link SubjectConfirmation} da controllare
	 * @param idpDestinationUrl - Destination URL verso chui tutte le SAML Response devono puntare ed è coindidente con AssertionConsumerServiceURL della SAML Request inviata a SPID.
	 * @param conditions -Le {@link Conditions} che devono essere rispettate dal {@link SubjectConfirmationData}
	 * @throws SpidCheckerException -sollevata se qualche controllo fallisce
	 */
	private static void checkSamlResponseSubjectConfirmation(Response samlResponse, String assertionId,	List<SubjectConfirmation> subjectConfirmations, String idpDestinationUrl, Conditions conditions) throws SpidCheckerException {
		if( conditions == null ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". Conditions nulle SAML Response non valida.");
		}
		for (SubjectConfirmation subjectConfirmation : subjectConfirmations) {
			String method = subjectConfirmation.getMethod();
			if( StringUtil.isEmptyString(method) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmation method null o vuoto ["+method+"] SAML Response non valida.");
			}else if( !SubjectConfirmation.METHOD_BEARER.equals(method) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmation method ["+method+"] differente da ["+SubjectConfirmation.METHOD_BEARER+"] SAML Response non valida.");
			}
			SubjectConfirmationData scd = subjectConfirmation.getSubjectConfirmationData();
			if( scd == null ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData nullo o vuoto ["+scd+"] SAML Response non valida.");
			}
			String scdRecipient = scd.getRecipient();
			if( StringUtil.isEmptyString(scdRecipient) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData recipient null o vuoto ["+scdRecipient+"] SAML Response non valida.");
			}else if( !idpDestinationUrl.equals(scdRecipient) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData recipient ["+scdRecipient+"] differente da ["+idpDestinationUrl+"] SAML Response non valida.");
			}
			String scdResponseTo = scd.getInResponseTo();
			if( StringUtil.isEmptyString(scdResponseTo) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData inResponseTo null o vuoto ["+scdResponseTo+"] SAML Response non valida.");
			}else if( !samlResponse.getInResponseTo().equals(scdResponseTo) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData inResponseTo ["+scdResponseTo+"] differente da ["+samlResponse.getInResponseTo()+"] SAML Response non valida.");
			}
			DateTime scdNotOnOrAfter = null;
			try {
				scdNotOnOrAfter = scd.getNotOnOrAfter();
			} catch (Exception e) {
				logger.error("Errore nel recupero di scdNotOnOrAfter", e);
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData NotOnOrAfter con formato non valido SAML Response non valida.");
			}
			if( scdNotOnOrAfter == null ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData NotOnOrAfter null SAML Response non valida.");
			}
			DateTime condNotOnOrAfter = conditions.getNotOnOrAfter();
			if( scdNotOnOrAfter.isBefore(condNotOnOrAfter) ) {
				throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" Assertion ID "+assertionId+". SubjectConfirmationData NotOnOrAfter "+scdNotOnOrAfter+" precedente a NotOnOrAfter della ricezione della response "+condNotOnOrAfter+" SAML Response non valida.");
			}
		}
	}
	/**
	 * Effettua i controlli sullo {@link Issuer} della {@link Response} SAML
	 * @param samlResponse -la {@link Response} da controllare
	 * @param spidIdpEntityId -l'ID dell'IDP SPID che deve coincidere con il valore dello {@link Issuer} della {@link Response}
	 * @throws SpidCheckerException -sollevata se qualche controllo fallisce
	 */
	private static void checkSamlResponseIssuer(Response samlResponse, String spidIdpEntityId) throws SpidCheckerException {
		Issuer responseIssuer = samlResponse.getIssuer();
		if( responseIssuer == null ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" elemento issuer non presente ["+responseIssuer+"] SAML Response non valida");
		}
		String responseIssuerValue = responseIssuer.getValue();
		if( !responseIssuerValue.equals(spidIdpEntityId) ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" valore issuer response ["+responseIssuerValue+"] non coincidente con valore IDP selezionato ["+spidIdpEntityId+"] SAML Response non valida");
		}
		String responseIssuerFormat = responseIssuer.getFormat();
		if( StringUtil.isEmptyString(responseIssuerFormat) ) {
			if( logger.isWarnEnabled() ) {

				logger.warn("SAML Response ID "+samlResponse.getID()+" format issuer response ["+responseIssuerFormat+"] vuoto o nullo SAML Response non valida");
			}
		}else if( !NameIDType.ENTITY.equals(responseIssuerFormat) ) {
			throw new SpidCheckerException("SAML Response ID "+samlResponse.getID()+" format issuer response ["+responseIssuerFormat+"] non coincidente con ["+NameIDType.ENTITY+"] SAML Response non valida");
		}
	}
	/**
	 * Effettua i controlli SPID sullo {@link Status} della {@link Response} saml
	 * @param samlResponse - La {@link Response} da controllare
	 * @throws SpidCheckerException sollevata se uno dei controlli fallisce
	 */
	private static void checkSamlResponseStatus(Response samlResponse) throws SpidCheckerException {
		Status status = samlResponse.getStatus();
		String responseId = samlResponse.getID();
		if( status == null || !status.hasChildren() ) {
			throw new SpidCheckerException("SAML Response ID "+responseId+" elemento status non presente ["+status+"] SAML Response non valida");
		}
		StatusCode statusCode = status.getStatusCode();

		if( statusCode == null ) {
			throw new SpidCheckerException("SAML Response ID "+responseId+" elemento status code non presente ["+statusCode+"] SAML Response non valida");
		}else if( StringUtil.isEmptyString(statusCode.getValue()) ) {
			throw new SpidCheckerException("SAML Response ID "+responseId+" valude di status code non presente ["+statusCode.getValue()+"] SAML Response non valida");
		}
		String statusCodeValue = statusCode.getValue();
		if( StringUtil.isEmptyString(statusCodeValue) ) {
			throw new SpidCheckerException("SAML Response ID "+responseId+" elemento value status code non presente o vuoto ["+statusCodeValue+"] SAML Response non valida");
		}else if( statusCodeValue.equals(StatusCode.RESPONDER) ) {

			//Controllo se sono anomalie utente
			//Gestisco le anomalie SPID Custom
			/*
      			<samlp:Status>			  
  				   	<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
  	            		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>
  	        		</samlp:StatusCode>
  	        		<samlp:StatusMessage>
  	            		ErrorCode nr22
  	        		</samlp:StatusMessage>
      			</samlp:Status>
			 * */
			if( statusCode.getStatusCode() != null && 
				!StringUtil.isEmptyString(statusCode.getStatusCode().getValue()) && 
				statusCode.getStatusCode().getValue().equals(StatusCode.AUTHN_FAILED) ) {
				StatusMessage sm = status.getStatusMessage();
				if( sm != null ) {
					String smValue = sm.getMessage();
					if( !StringUtil.isEmptyString(smValue) ) {
						if( logger.isWarnEnabled() ) {
							logger.warn("SAML Response ID {} StatusCode {} StatusMessage {}", responseId, statusCodeValue, smValue);
						}

						if( smValue.indexOf("ErrorCode nr") > -1 ) {

							throw new SpidCheckerException(Integer.parseInt(smValue.replaceAll("ErrorCode nr", "")), "SAML Response ID "+responseId+" elemento value status code  ["+statusCodeValue+"] differente da "+StatusCode.SUCCESS+" SAML Response non valida");
						}
					}
				}
			}
		}
		else if( !statusCodeValue.equals(StatusCode.SUCCESS) ) {
			throw new SpidCheckerException("SAML Response ID "+responseId+" elemento value status code  ["+statusCodeValue+"] differente da "+StatusCode.SUCCESS+" SAML Response non valida");
		}

	}
	/**
	 * Controlla il valore dell'attributo destination della SAML Response {@link Response}
	 * @param samlResponse -la {@link Response} da controllare
	 * @param idpDestinationUrl la destination URL dell'IDP
	 * @throws SpidCheckerException -sollevata se il controllo va male
	 */
	private static void checkSamlResponseDestination(Response samlResponse, String idpDestinationUrl) throws SpidCheckerException {
		String destination = samlResponse.getDestination();
		String responseId = samlResponse.getID();
		if( StringUtil.isEmptyString(destination) ) {
			throw new SpidCheckerException("SAML Response ID "+responseId+" destination non presente ["+destination+"] SAML Response non valida");
		}
		if( !destination.equals(idpDestinationUrl) ) {

			throw new SpidCheckerException("SAML Response ID "+responseId+" destination ["+destination+"] non coincidente con destination IDP censita ["+idpDestinationUrl+"] SAML Response non valida");
		}
	}
	/**
	 * Controlla l'issue instant della SAML Response {@link Response}
	 * @param responseIssueInstant -il {@link DateTime} rappresentante l'issue instant della SAML response
	 * @param assertions -Il {@link List} di {@link Assertion} dove controllare l'authn issue instant
	 * @param tolleranceTimeMillisecond -Il tempo di tolleranza in millisecondi entro cui la saml response è considerata corretta 
	 * @throws SpidCheckerException -sollevata se uno dei controlli fallisce
	 */
	private static void checkSamlResponseIssueInstant(final DateTime responseIssueInstant, final List<Assertion> assertions, final int tolleranceTimeMillisecond ) throws SpidCheckerException {
		if( responseIssueInstant == null ) {
			throw new SpidCheckerException("SAML Response issue instant non presente ["+responseIssueInstant+"] SAML Response non valida");
		}
		//Check se issue instant è precedente o successivo a quello della saml request
		for (Assertion assertion : assertions) {

			List<AuthnStatement> statemens = assertion.getAuthnStatements();
			for (AuthnStatement statement : statemens) {

				DateTime authnIssueInstant = statement.getAuthnInstant();
				DateTime authnIssueInstantRangeMinus = authnIssueInstant.minusMillis(tolleranceTimeMillisecond);
				if( authnIssueInstantRangeMinus.isAfter(responseIssueInstant) ) {
					throw new SpidCheckerException("Assertion ID "+assertion.getID()+". Response Issue Instant ["+responseIssueInstant+"] AuthnIssueInstant ["+authnIssueInstantRangeMinus+"] SAML Response non valida. Issue Instant della SAML Response precedente a quello della request");
				}
				DateTime authnIssueInstantRangePlus = authnIssueInstant.plusMillis(tolleranceTimeMillisecond);
				if( authnIssueInstantRangePlus.isBefore(responseIssueInstant) ) {
					throw new SpidCheckerException("Assertion ID "+assertion.getID()+". Response Issue Instant ["+responseIssueInstant+"] AuthnIssueInstant ["+authnIssueInstantRangePlus+"] SAML Response non valida. Issue Instant della SAML Response successivo a quello della request");
				}
			}
		}
	}
	private static List<Assertion> decriptAssertion( List<EncryptedAssertion> encAssertions, KeyPair keyPair ){
		List<Assertion> result = new ArrayList<>(encAssertions.size());
		Credential spCredentials = CredentialSupport.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());
		encAssertions.forEach(encAss ->{
			StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(spCredentials);
			Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
			decrypter.setRootInNewDocument(true);
			try {
				result.add(decrypter.decrypt(encAss));
			} catch (DecryptionException e) {
				throw new RuntimeException(e);
			}
		});
		return result;
	}

}