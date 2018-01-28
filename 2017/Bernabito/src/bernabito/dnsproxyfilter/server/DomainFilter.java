package bernabito.dnsproxyfilter.server;

import bernabito.dnsproxyfilter.server.exceptions.IllegalDomainSyntaxException;

import java.io.*;
import java.util.TreeMap;

/**
 * Autore: Matteo Bernabito
 * Classe che implementa la struttura per la "blacklist" dei domini.
 * La struttura usata è una struttura ricorsiva basata su TreeMap.
 * Abbiamo una TreeMap che ha come chiavi i label del dominio (es.: it, com, uk, al primo livello) e come
 * valori associati una TreeMap fatta allo stesso modo contenente a sua volta i label dei subdomain.
 *
 * Esempio semplificato di una blacklist di domini che blocca Google Drive e Google Mail.
 *
 *                                        com
 *                                         |
 *                                         |
 *                                       google
 *                                        / \
 *                                       /   \
 *                                      /     \
 *                                   drive   gmail
 *
 * Per stabilire se un dominio è presente o no nella blacklist dovrò guardare il dominio che sto cercando "al contrario":
 * ad esempio se devo controllare se "gmail.google.com" è filtrato parto dalla radice e trovo "com", scendo e trovo "google",
 * scendo ancora e trovo anche "gmail", a questo punto il dominio è interamente matchato e quindi blacklistato.
 */

public class DomainFilter {

    private DomainTree root;
    private final static String WILDCARD = "*";
    private final static char WILDCARD_CHAR = '*';

    public DomainFilter() {
        root = new DomainTree();
    }

    public DomainFilter addFilteredDomain(String domain) throws IllegalDomainSyntaxException{
        if(domain == null)
            throw new NullPointerException();
        domain = domain.toLowerCase();
        if(!validateDomainSyntax(domain)) {
            if(domain.compareTo(WILDCARD) != 0) {
                if(!(domain.length() >= 2 && domain.charAt(0) == WILDCARD_CHAR && domain.charAt(1) == '.' && validateDomainSyntax(domain.substring(2, domain.length()))))
                    throw new IllegalDomainSyntaxException();
            }
        }
        String[] domainParts = domain.split("\\.");
        int i = domainParts.length - 1;
        DomainTree currentNode = root;
        while(i >= 0) {
            // Se c'è una wildcard è inutile inserire il dominio a "questo livello"
            if(currentNode.get(WILDCARD) != null)
                return this;
            DomainTree sub = currentNode.get(domainParts[i]);
            // Se il nodo non è già presente
            if(sub == null) {
                // Se devo inserire una wildcard, cancello tutti gli altri nodi di "questo livello", tanto matcheranno comunque tutti
                if(i == 0 && domainParts[0].compareTo(WILDCARD) == 0)
                    currentNode.clear().put(WILDCARD);
                else
                    currentNode = currentNode.put(domainParts[i]);
            }
            else
                currentNode = sub;
            if(i == 0 && domainParts[0].compareTo(WILDCARD) != 0)
                currentNode.setExactMatching(true);
            i--;
        }
        return this;
    }

    public boolean isFiltered(String domain) throws IllegalDomainSyntaxException {
        if(domain == null)
            throw new NullPointerException();
        domain = domain.toLowerCase();
        if(!validateDomainSyntax(domain))
            throw new IllegalDomainSyntaxException();

        String[] domainParts = domain.split("\\.");
        int i = domainParts.length - 1;
        DomainTree currentNode = root;
        while(i >= 0) {
            // Se c'è una wildcard a "questo livello" matcha per forza
            if(currentNode.get(WILDCARD) != null)
                return true;
            // Altrimenti cerco nel sotto-albero
            DomainTree sub = currentNode.get(domainParts[i]);
            // Se non è presente allora non è filtrato
            if(sub == null)
                return false;
            currentNode = sub;
            i--;
        }
        if(currentNode.get(WILDCARD) != null)
            return true;
        else
            return currentNode.isExactMatching();
    }

    public void clearAll() {
        root.clear();
    }

    public static DomainFilter loadFromFile(String filePath) throws IOException, IllegalDomainSyntaxException{
        DomainFilter domainFilter = new DomainFilter();
        return loadFromStream(new FileInputStream(filePath));
    }

    public static DomainFilter loadFromStream(InputStream inputStream) throws IOException, IllegalDomainSyntaxException {
        DomainFilter domainFilter = new DomainFilter();
        try(BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line = bufferedReader.readLine();
            int lineNumber = 1;
            while(line != null) {
                if(!line.isEmpty()) {
                    try {
                        domainFilter.addFilteredDomain(line);
                    } catch (IllegalDomainSyntaxException e) {
                        throw new IllegalDomainSyntaxException("Illegal domain syntax at line " + lineNumber);
                    }
                }
                line = bufferedReader.readLine();
                lineNumber++;
            }
        }
        return domainFilter;

    }

    private static boolean validateDomainSyntax(String domain) {
        // Regex per il controllo della valità sintattica di un dominio
        // Source: https://stackoverflow.com/a/41193739
        return domain.matches("^(?=.{1,253}\\.?$)(?:(?!-|[^.]+_)[A-Za-z0-9-_]{1,63}(?<!-)(?:\\.|$)){2,}$");
    }


    /**
     * Classe privata interna che rappresenta "l'albero" dei domini.
     */

    private class DomainTree {

        private TreeMap<String, DomainTree> root;
        private boolean exactMatching = false;

        DomainTree() {
            root = new TreeMap<>();
        }

        DomainTree get(String partialDomain) {
            return root.get(partialDomain);
        }

        DomainTree put(String partialDomain) {
            DomainTree sub = new DomainTree();
            root.put(partialDomain, sub);
            return sub;
        }

        DomainTree clear() {
            root.clear();
            return this;
        }

        public boolean isExactMatching() {
            return exactMatching;
        }

        public void setExactMatching(boolean exactMatching) {
            this.exactMatching = exactMatching;
        }
    }
}
