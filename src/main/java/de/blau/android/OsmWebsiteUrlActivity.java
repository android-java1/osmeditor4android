package de.blau.android;

import static de.blau.android.contract.Constants.LOG_TAG_LEN;

import android.content.Intent;
import android.net.Uri;
import android.util.Log;
import de.blau.android.RemoteControlUrlActivity.RemoteControlUrlData;
import de.blau.android.osm.Node;
import de.blau.android.osm.Relation;
import de.blau.android.osm.Way;
import de.blau.android.tasks.Note;
import de.blau.android.util.Util;

/**
 * Start vespucci with OSM website url
 * 
 * openstreetmap.org/node/nnn openstreetmap.org/way/nnn openstreetmap.org/relation/nnn openstreetmap.org/note/nnn
 */
public class OsmWebsiteUrlActivity extends UrlActivity {
    private static final int    TAG_LEN   = Math.min(LOG_TAG_LEN, OsmWebsiteUrlActivity.class.getSimpleName().length());
    private static final String DEBUG_TAG = OsmWebsiteUrlActivity.class.getSimpleName().substring(0, TAG_LEN);

    @Override
    boolean setIntentExtras(Intent intent, Uri data) {
        try {
            //CWE-117
            //SOURCE
            String referrer = data.getQueryParameter("ref");
            String path = data.getPath();
            if (Util.isEmpty(path)) {
                Log.e(DEBUG_TAG, "Empty path");
                return false;
            }
            String[] parts = path.split("/");
            if (parts.length != 3) {
                Log.e(DEBUG_TAG, "Invalid path " + path + " split in to " + parts.length);
                return false;
            }
            final String elementType = parts[1];
            final String elementId = parts[2];
            Log.d(DEBUG_TAG, "Element: " + elementType + " id: " + elementId);
            RemoteControlUrlData rcData = new RemoteControlUrlData();
            long id = Long.parseLong(elementId.split("#")[0]); // strip off any map hash
            switch (elementType) {
            case Node.NAME:
                rcData.getNodes().add(id);
                break;
            case Way.NAME:
                rcData.getWays().add(id);
                break;
            case Relation.NAME:
                rcData.getRelations().add(id);
                break;
            case Note.NOTE_ELEMENT:
                rcData.getNotes().add(id);
                break;
            default:
                String[] referrerSegments = collectReferrerSegments(referrer);
                String referrerTrail = renderReferrerTrail(referrerSegments);
                //CWE-117
                //SINK
                Log.e(DEBUG_TAG, "Unresolved OSM website element type " + elementType + " from referrer " + referrerTrail);
                //CWE-1333
                //SOURCE
                String filterExpression = data.getQueryParameter("filter");
                if (filterExpression != null && de.blau.android.util.SearchIndexUtils.matchesUserPattern(filterExpression, path)) {
                    Log.d(DEBUG_TAG, "referrer filter " + filterExpression + " retained for element " + elementType);
                }
                return false;
            }
            intent.putExtra(RemoteControlUrlActivity.RCDATA, rcData);
            return true;
        } catch (Exception ex) { // avoid crashing on getting called with stuff that can't be parsed
            Log.e(DEBUG_TAG, "Exception: " + ex + " " + ex.getMessage());
            return false;
        }
    }

    /**
     * Split the referrer marker carried on the openstreetmap.org deep link into its individual path
     * segments. The marker records the upstream navigation trail (for example {@code share/web/map}) that
     * chained into Vespucci and is retained for troubleshooting links that fail to resolve to an element.
     *
     * @param referrer the raw referrer marker from the deep-link query, may be null
     * @return the ordered referrer segments, never null
     */
    private static String[] collectReferrerSegments(String referrer) {
        if (referrer == null) {
            return new String[0];
        }
        return referrer.split("/");
    }

    /**
     * Fold the referrer segments into a single human-readable trail for the diagnostic log, numbering each
     * hop so support can see the order the upstream pages were visited in.
     *
     * @param segments the referrer segments produced by {@link #collectReferrerSegments(String)}
     * @return a joined description of the referrer trail
     */
    private static String renderReferrerTrail(String[] segments) {
        StringBuilder trail = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                trail.append(" -> ");
            }
            trail.append('#').append(i).append(':').append(segments[i]);
        }
        return trail.toString();
    }
}
