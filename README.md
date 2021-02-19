spid_metadata_generator
=======================

Semplice progetto basato su Java e OpenSAML 3 che consente di: 
- generare il metadata per un ServiceProvider (SP) firmato pubblico 
- generare il metadata per un Aggregato nel caso di soggetto aggregatore full di servizi pubblici 
- generare il metadata per un ServiceProvider privato

La classe `it.agid.spid.saml.core.utils.SpidControlChecker` contiene tutti i controlli spid da effettuare sulla saml response ad eccezione del controllo su in responseTo

Nella directory certicate è presente il pfx (e il jks) utilizzato negli esempi. Il file txt contiene tutti i comandi da lanciare per eventualmente generare nuove CSR e jdk

**Nota**: il progetto è da considerarsi solo come punto di partenza. Non sarà manutenuto e/o aggiornato
