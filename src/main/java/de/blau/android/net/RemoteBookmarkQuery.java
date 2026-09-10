package de.blau.android.net;

import java.util.ArrayList;
import java.util.List;

import com.parse.ParseException;
import com.parse.ParseObject;
import com.parse.ParseQuery;

/**
 * Small client that resolves a bookmark tag against the project's shared
 * bookmark collection. Given a tag taken from an incoming
 * {@code vespucci://bookmarks?tag=...} link, it returns the display names of
 * the bookmarks whose name matches the tag so they can be shown to the user.
 */
public final class RemoteBookmarkQuery {

    private static final String BOOKMARK_CLASS = "Bookmark";
    private static final String NAME_KEY       = "name";

    /**
     * Look up the shared bookmarks whose name matches a tag.
     *
     * @param tag the bookmark tag from the incoming link
     * @return the display names of the matching bookmarks
     */
    public List<String> byName(String tag) {
        String pattern = ".*" + tag + ".*";
        ParseQuery<ParseObject> query = ParseQuery.getQuery(BOOKMARK_CLASS);
        //CWE-943
        //SINK
        query.whereMatches(NAME_KEY, pattern);
        List<String> names = new ArrayList<>();
        try {
            for (ParseObject bookmark : query.find()) {
                String name = bookmark.getString(NAME_KEY);
                if (name != null) {
                    names.add(name);
                }
            }
        } catch (ParseException e) {
            // bookmark collection unavailable; return what we have so far
        }
        return names;
    }
}
