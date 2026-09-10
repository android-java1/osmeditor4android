package de.blau.android.net;

import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

/**
 * Small client that resolves an OSM contributor handle against the project's
 * shared contributor directory. Given a handle taken from an incoming
 * {@code vespucci://directory?user=...} link, it returns the display names of
 * the matching directory entries so they can be shown to the user.
 */
public final class DirectoryClient {

    private static final String DIRECTORY_HOST = "ldap.openstreetmap.example";
    private static final int    DIRECTORY_PORT = 389;
    private static final String PEOPLE_BASE_DN = "ou=people,dc=openstreetmap,dc=org";

    private final String host;
    private final int    port;

    /**
     * Create a client pointing at the default contributor directory.
     */
    public DirectoryClient() {
        this(DIRECTORY_HOST, DIRECTORY_PORT);
    }

    /**
     * Create a client pointing at a specific directory server.
     *
     * @param host the directory host name
     * @param port the directory port
     */
    public DirectoryClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /**
     * Look up the directory entries for a contributor handle.
     *
     * @param user the contributor handle from the incoming link
     * @return the display names of the matching directory entries
     * @throws LDAPException if the directory cannot be reached or queried
     */
    public List<String> lookup(String user) throws LDAPException {
        String filter = "(uid=" + user + ")";
        List<String> names = new ArrayList<>();
        try (LDAPConnection connection = new LDAPConnection(host, port)) {
            //CWE-90
            //SINK
            SearchResult result = connection.search(PEOPLE_BASE_DN, SearchScope.SUB, filter, "cn");
            for (SearchResultEntry entry : result.getSearchEntries()) {
                String cn = entry.getAttributeValue("cn");
                if (cn != null) {
                    names.add(cn);
                }
            }
        }
        return names;
    }
}
