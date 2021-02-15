package it.agid.spid.saml.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import javax.xml.crypto.dsig.DigestMethod;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import it.agid.spid.saml.core.utils.InsertBeforeElementEnum;

public abstract class AbstractMetadataBuilder {
	/**
	 * Partendo dalla stringa in ingresso genera la stringa del metadata firmata XML-Sig
	 * @param orignalMetadata -la stringa rappresentante il metadata non firmato
	 * @param privateKey -la {@link PrivateKey} da utilizzare per la firma
	 * @param cert -il {@link java.security.cert.X509Certificate} da utilizzare per la firma
	 * @param baseUri - il base uri di default
	 * @param inserBefore -Indica il nome dell'elemento prima del quale inserire la firma del metadata. Può assumere uno dei valori dell'enum {@link InsertBeforeElementEnum}e
	 * @return -La stringa rappresentante il metadata firmato
	 * @throws Exception sollevata in caso di errore.
	 */
	public String signMetadata( String orignalMetadata, String generatedId, PrivateKey privateKey, java.security.cert.X509Certificate cert, String baseUri, InsertBeforeElementEnum inserBefore ) throws Exception{
		//String generatedId = OpenSAMLUtils.generateSecureRandomId();
		javax.xml.parsers.DocumentBuilderFactory dbf =	javax.xml.parsers.DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(new ByteArrayInputStream(orignalMetadata.getBytes()));
		//Devo evitare di far leggere l'ID al parser. Lo faccio in questo modo
		doc.getDocumentElement().setIdAttribute("ID", true);
		XMLSignature sig = new XMLSignature(doc, baseUri, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
		Element root = doc.getDocumentElement();
		//Vado alla ricerca del primo elemento che ha nome passato in ingresso ed inserisco la firma prima di questo elemento
		root.insertBefore(sig.getElement(), root.getElementsByTagNameNS(inserBefore.getNameSpace(),inserBefore.getElementName()).item(0));
		sig.getSignedInfo().addResourceResolver(new ResolverLocalFilesystem());
		Transforms transforms = new Transforms(doc);
		transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		//transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
		sig.addDocument("#"+generatedId, transforms, DigestMethod.SHA512);
		sig.addKeyInfo(cert);
		sig.addKeyInfo(cert.getPublicKey());
		sig.sign(privateKey);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLUtils.outputDOM(doc, baos, true);
		return baos.toString(StandardCharsets.UTF_8);
	}
}
