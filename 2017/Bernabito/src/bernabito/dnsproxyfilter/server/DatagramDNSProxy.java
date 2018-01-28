package bernabito.dnsproxyfilter.server;

import bernabito.dnsproxyfilter.protocol.DNSQuery;
import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSHeaderException;
import bernabito.dnsproxyfilter.protocol.exceptions.MalformedDNSQueryException;
import bernabito.dnsproxyfilter.protocol.exceptions.MismatchingProtocolException;
import bernabito.dnsproxyfilter.rfc.DNSProperties;
import bernabito.dnsproxyfilter.rfc.ResponseType;
import bernabito.dnsproxyfilter.server.exceptions.IllegalDomainSyntaxException;
import bernabito.dnsproxyfilter.util.CustomLogger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/**
 * Autore: Matteo Bernabito
 * Classe che implementa un proxy DNS multi-threaded su protocollo UDP.
 * Sono presenti varie impostazioni per il server-proxy tra cui:
 *      - La lista dei DNS a cui forwardare le richieste
 *      - La possibilità di impostare un filtro per dominio
 *      - Il timeout per i socket che forwardano le richieste e attendono una risposta
 *      - Il numero di thread concorrenti
 *      - La porta e l'indirizzo su cui bindare il server
 */

public class DatagramDNSProxy extends Thread {

    public static final int DEFAULT_THREAD_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    public static final int DEFAULT_DNS_REPLY_TIMEOUT = 500;
    public static final byte[] DEFAULT_DNS_SERVER_1 = new byte[]{8,8,8,8};
    public static final byte[] DEFAULT_DNS_SERVER_2 = new byte[]{8,8,4,4};

    private DatagramSocket serverSocket;
    private InetAddress[] forwardDNSPool;
    private ExecutorService threadPool;
    private DomainFilter domainFilter;
    private int dnsReplyTimeout;
    private int forwardPort;

    public DatagramDNSProxy() throws SocketException {
        this(DNSProperties.DNS_UDP_PORT, null, null, DEFAULT_THREAD_POOL_SIZE);
    }

    public DatagramDNSProxy(int listeningPort) throws SocketException {
        this(listeningPort, null, null, DEFAULT_THREAD_POOL_SIZE);
    }

    public DatagramDNSProxy(int listeningPort, InetAddress bindingAddress, Collection<InetAddress> forwardDNSPool) throws SocketException {
        this(listeningPort, bindingAddress, forwardDNSPool, DEFAULT_THREAD_POOL_SIZE);
    }

    public DatagramDNSProxy(int listeningPort, InetAddress bindingAddress, Collection<InetAddress> forwardDNSPool, int threadPoolSize) throws SocketException {
        this(listeningPort, bindingAddress, forwardDNSPool, threadPoolSize, DNSProperties.DNS_UDP_PORT);
    }

    public DatagramDNSProxy(int listeningPort, InetAddress bindingAddress, Collection<InetAddress> forwardDNSPool, int threadPoolSize, int forwardPort) throws SocketException {
      if(bindingAddress == null)
          serverSocket = new DatagramSocket(listeningPort);
      else
          serverSocket = new DatagramSocket(listeningPort, bindingAddress);
      if(forwardDNSPool == null) {
          this.forwardDNSPool = new InetAddress[2];
          try {
              this.forwardDNSPool[0] = InetAddress.getByAddress(DEFAULT_DNS_SERVER_1);
              this.forwardDNSPool[1] = InetAddress.getByAddress(DEFAULT_DNS_SERVER_2);
          } catch (UnknownHostException ignored) { }
      }
      else {
          Set<InetAddress> setForwardDNSPool = new HashSet<>(forwardDNSPool);
          this.forwardDNSPool = new InetAddress[forwardDNSPool.size()];
          int i = 0;
          for(InetAddress dnsServer : setForwardDNSPool) {
              this.forwardDNSPool[i] = dnsServer;
              i++;
          }
      }
      threadPool = Executors.newFixedThreadPool(threadPoolSize);
      dnsReplyTimeout = DEFAULT_DNS_REPLY_TIMEOUT;
      this.forwardPort = forwardPort;
    }

    public DatagramDNSProxy setDnsReplyTimeout(int time) {
        if(time > 0)
            dnsReplyTimeout = time;
        return this;
    }

    public DatagramDNSProxy applyDomainFilter(DomainFilter domainFilter) {
        this.domainFilter = domainFilter;
        return this;
    }

    @Override
    public void run() {
        CustomLogger.getLogger().log(Level.INFO, "UDP DNS proxy up and running on port " + serverSocket.getLocalPort());
        while (!Thread.currentThread().isInterrupted()) {
            try {
                byte[] packetBuffer = new byte[DNSProperties.UDP_MAX_LENGTH];
                DatagramPacket packet = new DatagramPacket(packetBuffer, 0, packetBuffer.length);
                serverSocket.receive(packet);
                threadPool.execute(new ProxyRequestWorker(packet));
            } catch (IOException e) {
                CustomLogger.getLogger().log(Level.SEVERE, "Critical error in main loop, " + e.getMessage());
            }
        }
        threadPool.shutdownNow();
        try { threadPool.awaitTermination(dnsReplyTimeout * forwardDNSPool.length, TimeUnit.MILLISECONDS); }
        catch (InterruptedException ignored) {}
        serverSocket.close();
        CustomLogger.getLogger().log(Level.INFO, "UDP DNS proxy shutted down");
    }

    @Override
    public void interrupt() {
        super.interrupt();
        serverSocket.close();
    }

    private class ProxyRequestWorker implements Runnable {

        private DatagramPacket packet;

        public ProxyRequestWorker(DatagramPacket packet) {
            this.packet = packet;
        }

        @Override
        public void run() {
            long startProcessingTime = System.currentTimeMillis();
            DNSQuery query = null;
            try {
                query = DNSQuery.tryParse(new ByteArrayInputStream(packet.getData(), packet.getOffset(), packet.getLength()));
            } catch (MalformedDNSQueryException | MismatchingProtocolException | MalformedDNSHeaderException | IOException e) {
                CustomLogger.getLogger().log(Level.WARNING, e.getClass().getSimpleName() + " caused from " + packet.getAddress() + ", message: " + e.getMessage());
            }

            if(query != null) {
                CustomLogger.getLogger().log(Level.INFO, "Query type " + query.getQueryType() + " " + query.getQueryString() + " from " + packet.getAddress());
                InetAddress sourceAddress = packet.getAddress();
                int sourcePort = packet.getPort();
                boolean isFiltered = false;
                boolean gotSomethingToSend = false;

                try {
                    if(domainFilter != null)
                        if(domainFilter.isFiltered(query.getQueryString()))
                            isFiltered = true;
                } catch (IllegalDomainSyntaxException ignored) { }

                if(isFiltered) {
                    CustomLogger.getLogger().log(Level.INFO, "Filtering request of " + query.getQueryString() + " from " + packet.getAddress());
                    query.getHeader().setQuery(false)
                                     .setAnswerCount(0)
                                     .setAuthorityNameserversCount(0)
                                     .setAdditionalRecordsCount(0)
                                     .setResponseType(ResponseType.NAME_ERROR);
                    packet.setData(query.toByteArray());
                    gotSomethingToSend = true;
                }

                else {
                    packet.setPort(forwardPort);
                    try (DatagramSocket forwardSocket = new DatagramSocket()) {
                        forwardSocket.setSoTimeout(dnsReplyTimeout);
                        int forwardServerIndex = 0;
                        boolean resolved = false;
                        // Strategia fail-over, forwardo dal primo all'ultimo server
                        while (forwardServerIndex < forwardDNSPool.length && !resolved) {
                            packet.setAddress(forwardDNSPool[forwardServerIndex]);
                            forwardSocket.send(packet);
                            try {
                                forwardSocket.receive(packet);
                                resolved = true;
                            } catch (SocketTimeoutException e) {
                                CustomLogger.getLogger().log(Level.WARNING, "DNS Server " + packet.getAddress() + " didn't answer");
                                forwardServerIndex++;
                            }
                        }
                        if (resolved) {
                            packet.setAddress(sourceAddress);
                            packet.setPort(sourcePort);
                            gotSomethingToSend = true;
                        } else {
                            CustomLogger.getLogger().log(Level.WARNING, "Query type " + query.getQueryType() + " " + query.getQueryString() + " unresolved");
                        }
                    } catch (IOException e) {
                        CustomLogger.getLogger().log(Level.SEVERE, e.getClass().getSimpleName() + " while forwarding DNS request to " + packet.getAddress() +  ", message: " + e.getMessage());
                    }
                }

                if(gotSomethingToSend) {
                    try {
                        serverSocket.send(packet);
                        long processingTime = System.currentTimeMillis() - startProcessingTime;
                        CustomLogger.getLogger().log(Level.FINE, "Query type " + query.getQueryType() + " " + query.getQueryString() + " from "
                                                     + packet.getAddress() + " processed in " + processingTime + " ms");
                    } catch (IOException e) {
                        CustomLogger.getLogger().log(Level.SEVERE, e.getClass().getSimpleName() + " while replying to client " + packet.getAddress() + ", message: " + e.getMessage());
                    }
                }
            }
        }
    }
}
