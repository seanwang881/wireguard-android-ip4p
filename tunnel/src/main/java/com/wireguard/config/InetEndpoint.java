/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config;

import com.wireguard.util.NonNullForAll;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;

import androidx.annotation.Nullable;

@NonNullForAll
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
    private static final String DNS_QUERY_URL = "https://dns.alidns.com/resolve?name=";
    private static final int DNS_TIMEOUT = 5000; // 5 seconds timeout

    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }
    // Add getHost() method
    public String getHost() {
        return host;
    }

    // Add getPort() method for completeness
    public int getPort() {
        return port;
    }

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "Forbidden characters");
        final URI uri;
        try {
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, e);
        }
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "Missing/invalid port number");
        try {
            InetAddresses.parse(uri.getHost());
            // Parsing the host as a numeric address worked, so we don't need to do DNS lookups.
            return new InetEndpoint(uri.getHost(), true, uri.getPort());
        } catch (final ParseException ignored) {
            // Failed to parse the host as a numeric address, so it must be a DNS hostname/FQDN.
            return new InetEndpoint(uri.getHost(), false, uri.getPort());
        }
    }

    public Optional<InetEndpoint> getResolved() {
        if (isResolved)
            return Optional.of(this);
        synchronized (lock) {
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                try {
                    InetAddress address = resolveAddress();
                    if (address != null) {
                        if (address instanceof Inet6Address) {
                            resolved = handleIP4P((Inet6Address) address);
                        } else {
                            resolved = new InetEndpoint(address.getHostAddress(), true, port);
                        }
                        lastResolution = Instant.now();
                    } else {
                        resolved = null;
                    }
                } catch (Exception e) {
                    System.err.println("Error resolving address: " + e.getMessage());
                    resolved = null;
                }
            }
            return Optional.ofNullable(resolved);
        }
    }

    private InetAddress resolveAddress() throws IOException {
        List<InetAddress> aRecords = queryDNS(host, "A");
        if (!aRecords.isEmpty()) {
            return aRecords.get(0); // Return the first A record
        }

        List<InetAddress> aaaaRecords = queryDNS(host, "AAAA");
        if (!aaaaRecords.isEmpty()) {
            return aaaaRecords.get(0); // Return the first AAAA record
        }

        throw new IOException("No A or AAAA records found for " + host);
    }

    private InetEndpoint handleIP4P(Inet6Address address) throws IOException {
        byte[] v6 = address.getAddress();
        if ((v6[0] == 0x20) && (v6[1] == 0x01) && (v6[2] == 0x00) && (v6[3] == 0x00)) {
            InetAddress v4 = InetAddress.getByAddress(Arrays.copyOfRange(v6, 12, 16));
            int p = ((v6[10] & 0xFF) << 8) | (v6[11] & 0xFF);
            return new InetEndpoint(v4.getHostAddress(), true, p);
        }
        return new InetEndpoint(address.getHostAddress(), true, port);
    }

    private List<InetAddress> queryDNS(String hostname, String type) throws IOException {
        String urlString = DNS_QUERY_URL + hostname + "&type=" + type;
        URL url = new URL(urlString);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(DNS_TIMEOUT);
        connection.setReadTimeout(DNS_TIMEOUT);

        try {
            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("DNS query failed. Response Code: " + responseCode);
            }

            String response = readResponse(connection);
            return parseAddresses(response);
        } finally {
            connection.disconnect();
        }
    }

    private String readResponse(HttpURLConnection connection) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }

    private List<InetAddress> parseAddresses(String jsonResponse) throws IOException {
        List<InetAddress> addresses = new ArrayList<>();
        String[] parts = jsonResponse.split("\"Answer\":\\[");
        if (parts.length > 1) {
            String[] records = parts[1].split("\\{");
            for (String record : records) {
                if (record.contains("\"data\":\"")) {
                    String ip = record.split("\"data\":\"")[1].split("\"")[0];
                    try {
                        addresses.add(InetAddress.getByName(ip));
                    } catch (Exception e) {
                        System.err.println("Failed to parse IP address: " + ip);
                    }
                }
            }
        }
        return addresses;
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}
