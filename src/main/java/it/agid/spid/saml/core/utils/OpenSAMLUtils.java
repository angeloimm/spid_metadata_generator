package it.agid.spid.saml.core.utils;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.cryptacular.util.CodecUtil;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class OpenSAMLUtils {
	private static Logger logger = LoggerFactory.getLogger(OpenSAMLUtils.class);
	private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

	static {
		secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
		Init.init();
	}
	/**
	 * Metodo da richiamare solo per inizializzare OpenSAML quando non si utilizza 
	 * Spring security con supporto saml
	 * @throws Exception -sollevato in caso di errore.
	 */
	public static void openSamlBootstrap() throws Exception{
		if( logger.isInfoEnabled() ) {
			logger.info("openSamlBootstrap - Inizializzazione JavaCryptoValidationInitializer");
		}
		JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
		javaCryptoValidationInitializer.init();
		if( logger.isTraceEnabled() ) {
			for (Provider jceProvider : Security.getProviders()) {
				logger.trace(jceProvider.getInfo());
			}
		}
		if( logger.isInfoEnabled() ) {
			logger.info("Inizializzazione OpenSAML");
		}
		InitializationService.initialize();
	}
	/**
	 * Si oppuca di costruire l'oggetto SAML indicato dalla classe passata in ingresso 
	 * @param <T>: il tipo di oggetto da creare
	 * @param clazz: classe del tipo di oggetto da creare
	 * @return L'oggetto SAML voluto
	 */
	@SuppressWarnings("unchecked")
	public static <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;
		try {
			XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
			QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		} catch (NoSuchFieldException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		}

		return object;
	}
	/**
	 * Genera un ID da utilizzare come ID nelle assertion saml
	 * @return l'ID generato
	 */
	public static String generateSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}
	/**
	 * Trasforma l'oggetto SAML in stringa XML
	 * @param object l'oggetto da trasformare
	 * @return -la stringa xml
	 */
	public static String samlObjectToString(final XMLObject object) {
		Element element = null;

		if (object instanceof SignableSAMLObject && ((SignableSAMLObject)object).isSigned() && object.getDOM() != null) {
			element = object.getDOM();
		} else {
			try {
				Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
				out.marshall(object);
				element = object.getDOM();

			} catch (MarshallingException e) {
				logger.error(e.getMessage(), e);
			}
		}

		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "no");
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(element);
			transformer.transform(source, result);
			String xmlString = result.getWriter().toString();
			return xmlString;
		} catch (Exception e) {
			logger.error("Errore durante la generazione della stringa XML rappresentante l'oggetto saml passato in ingresso", e);
			return null;
		}
	}
	/**
	 * Costruisce l'oggetto {@link AuthnRequest} partendo dalla stringa encodata in ingresso
	 * @param samlRequestString -la stringa da cui generare l'oggetto {@link AuthnRequest}
	 * @return - l'oggetto creato
	 * @throws Exception -sollevata in caso di errore
	 */
	public static AuthnRequest fromEncodedStringToAuthnRequestObi( final String samlRequestString ) throws Exception {

		byte[] samlToken = samlRequestString.getBytes(StandardCharsets.UTF_8);
		ByteArrayInputStream stream = new ByteArrayInputStream(samlToken); 
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder docBuilder = factory.newDocumentBuilder();
			Document samlDocument = docBuilder.parse(stream);
			Element samlElem = samlDocument.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElem);
			Object requestXmlObj = unmarshaller.unmarshall(samlElem);
			AuthnRequest authRequest = (AuthnRequest) requestXmlObj;
			return authRequest;
		}finally {
			if( stream != null ) {
				stream.close();
			}
		}
	}
	/**
	 * Partendo da un {@link InputStream} crea un oggetto SAML indicato dal tipo e dalla classe passati in ingresso
	 * @param <T> Il tipo di oggetto SAML da creare
	 * @param stream - {@link InputStream} da cui creare l'oggetto
	 * @param clazz -La classe del tipo di oggetto SAML
	 * @return l'oggetto saml creato
	 * @throws Exception -sollevata in caso di errore
	 */
	@SuppressWarnings("unchecked")
	public static <T> T fromInputStreamToSamlObject( final InputStream stream, final Class<T> clazz ) throws Exception{
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder docBuilder = factory.newDocumentBuilder();
			Document samlDocument = docBuilder.parse(stream);
			Element samlElem = samlDocument.getDocumentElement();
			removeRecursively(samlElem, Node.COMMENT_NODE, null);
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElem);
			Object requestXmlObj = unmarshaller.unmarshall(samlElem);
			T authRequest = (T) requestXmlObj;
			return authRequest;
		}finally {
			if( stream != null ) {
				stream.close();
			}
		}
	}
	/**
	 * Dalla request encodata restituisce l'XML della SAML request
	 * @param encodedSamlRequest -la request encodata
	 * @param useWrap -se utilizzare wrap o meno
	 * @return -l'XML della saml request decodificato
	 * @throws Exception -sollevata in caso di errore.
	 */
	public static String getSamlObjectAsString( final String encodedSamlRequest, boolean useWrap ) throws Exception {
		Inflater decompresser = new Inflater(useWrap);
		byte[] deflatedData = CodecUtil.b64(encodedSamlRequest);
		try {
			byte[] inflatedData = new byte[(10 * deflatedData.length)];
			decompresser.setInput(deflatedData, 0, deflatedData.length);
			int inflatedBytesLength = decompresser.inflate(inflatedData);
			return new String(inflatedData, 0, inflatedBytesLength);
		}catch (DataFormatException dfe) {
			logger.warn("Errore nel deflating della stringa saml {} Restituisco la stringa generata direttamente dal deflating", dfe.getMessage());
			return new String(deflatedData);
		}
		finally {
			decompresser.end();
		}
	}
	/**
	 * Rimuove ricorsivamebte dal document indicato da node il tipo di nodo con nome specificato. Se nome null, rimuove tutti i nodi di quel tipo
	 * @param node -il {@link Node} da cui rimuovere gli oggetti
	 * @param nodeType -Il tipo di nodo da rimuovere
	 * @param name -il nome del nodo. Se nullo viene rimosso solo il nodo del tipo specificato
	 */
	public static void removeRecursively(Node node, short nodeType, String name) {
        if (node.getNodeType()==nodeType && (name == null || node.getNodeName().equals(name))) {
            node.getParentNode().removeChild(node);
        }
        else {
            // check the children recursively
            NodeList list = node.getChildNodes();
            for (int i = 0; i < list.getLength(); i++) {
                removeRecursively(list.item(i), nodeType, name);
            }
        }
    }
	/**
	 * Firma il {@link SignableXMLObject} in ingresso utilizzando {@link PrivateKey} e {@link X509Certificate} passati in ingresso
	 * @param signable -l'oggetto {@link SignableXMLObject} da firmare
	 * @param privateKey -la {@link PrivateKey} da utilizzare per la firma
	 * @param cert  -il {@link X509Certificate} da utilizzare per la firma
	 * @throws Exception -sollevata in caso di errore
	 */
	public static void signSamlObj(final SignableXMLObject signable, PrivateKey privateKey, java.security.cert.X509Certificate cert) throws Exception {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		X509Credential credential = new BasicX509Credential(cert, privateKey);
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_OMIT_COMMENTS);
		parameters.setKeyInfoGenerator(keyInfoGenerator());
		SignatureSupport.signObject(signable, parameters);
	}	
	/**
	 * Crea l'oggetto {@link KeyInfoGenerator} che si occupa di inserire il tag KeyInfo
	 * @return -il {@link KeyInfoGenerator} creato
	 */
	private static KeyInfoGenerator keyInfoGenerator() {
		X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
		generator.setEmitEntityCertificate(true);
		generator.setEmitEntityCertificateChain(true);
		return generator.newInstance();
	}
	/**
	 * Verifica la {@link Signature} utilizzando il {@link List} di {@link Credential} passato in ingresso
	 * @param signature -la {@link Signature} da verificare
	 * @param credentials il {@link List} di {@link Credential} da utilizzare per la verifica
	 * @return true se la {@link Signature} è valida, false altrimenti
	 */
	public static boolean isSignatureValid( Signature signature, List<Credential> credentials ) {
		for (Credential credential : credentials) {
			try {
				SignatureValidator.validate(signature, credential);
				if( logger.isTraceEnabled() ) {
					logger.trace("Signature valida ");
				}
				return true;
			}catch (Exception e) {
				if( logger.isTraceEnabled() ) {
					logger.trace("Signature non valida. ", e);
				}
			}
		}
		return false;
	}
}