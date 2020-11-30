/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.guacamole.auth.openid.user;

import com.google.inject.Inject;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.openid.OpenIDAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.*;
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.*;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

import java.util.*;
import java.util.stream.Collectors;

/**
 * An OpenID-specific implementation of UserContext which queries all Guacamole
 * connections and users from the ID Token.
 */
public class OpenIDUserContext extends AbstractUserContext {

    /**
     * Reference to the AuthenticationProvider associated with this
     * UserContext.
     */
    @Inject
    private AuthenticationProvider authProvider;

    /**
     * Reference to a User object representing the user whose access level
     * dictates the users and connections visible through this UserContext.
     */
    private User self;

    /**
     * Directory containing all User objects accessible to the user associated
     * with this UserContext.
     */
    private Directory<User> userDirectory;

    /**
     * Directory containing all UserGroup objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<UserGroup> userGroupDirectory;

    /**
     * Directory containing all Connection objects accessible to the user
     * associated with this UserContext.
     */
    private Directory<Connection> connectionDirectory;

    /**
     * Reference to the root connection group.
     */
    private ConnectionGroup rootGroup;

    /**
     * Initializes this UserContext using the provided AuthenticatedUser and
     * LdapNetworkConnection.
     *
     * @param user   The AuthenticatedUser representing the user that authenticated. This
     *               user may have been authenticated by a different authentication
     *               provider (not LDAP).
     * @param claims The connection to the LDAP server to use when querying accessible
     *               Guacamole users and connections.
     * @throws GuacamoleException If associated data stored within the LDAP directory cannot be
     *                            queried due to an error.
     */
    public void init(AuthenticatedUser user, JwtClaims claims)
            throws GuacamoleException {


        // Query all accessible users
        userDirectory = new SimpleDirectory<>(
                getUsers(user, claims)
        );

        // Query all accessible user groups
        userGroupDirectory = new SimpleDirectory<>(
                getUserGroups(user, claims)
        );

        // Query all accessible connections
        connectionDirectory = new SimpleDirectory<>(
                getConnections(user, claims)
        );

        // Root group contains only connections
        rootGroup = new SimpleConnectionGroup(
                OpenIDAuthenticationProvider.ROOT_CONNECTION_GROUP,
                OpenIDAuthenticationProvider.ROOT_CONNECTION_GROUP,
                connectionDirectory.getIdentifiers(),
                Collections.<String>emptyList()
        );

        // Init self with basic permissions
        self = new SimpleUser(user.getIdentifier()) {

            @Override
            public ObjectPermissionSet getUserPermissions() throws GuacamoleException {
                return new SimpleObjectPermissionSet(userDirectory.getIdentifiers());
            }

            @Override
            public ObjectPermissionSet getUserGroupPermissions() throws GuacamoleException {
                return new SimpleObjectPermissionSet(userGroupDirectory.getIdentifiers());
            }

            @Override
            public ObjectPermissionSet getConnectionPermissions() throws GuacamoleException {
                return new SimpleObjectPermissionSet(connectionDirectory.getIdentifiers());
            }

            @Override
            public ObjectPermissionSet getConnectionGroupPermissions() throws GuacamoleException {
                return new SimpleObjectPermissionSet(Collections.singleton(OpenIDAuthenticationProvider.ROOT_CONNECTION_GROUP));
            }

        };

    }

    private Map<String, User> getUsers(AuthenticatedUser user, JwtClaims claims) {
        Map<String, User> map = new HashMap<>();
        User u = new SimpleUser(user.getIdentifier());
        map.put(user.getIdentifier(), u);
        return map;
    }

    private Map<String, UserGroup> getUserGroups(AuthenticatedUser user, JwtClaims claims) {
        try {
            List<String> groups = claims.getStringListClaimValue("groups");
            Map<String, UserGroup> map = groups.stream()
                    .map(g -> new SimpleUserGroup(g))
                    .collect(Collectors.toMap(g -> g.getIdentifier(), g -> g));
            return map;
        } catch (MalformedClaimException e) {
            throw new RuntimeException(e);
        }
    }

    private Map<String, Connection> getConnections(AuthenticatedUser user, JwtClaims claims) {
        try {
            List<String> groups = claims.getStringListClaimValue("connections");
            Map<String, Connection> map = groups.stream()
                    .map(c -> {
                        Map<String, String> params = Arrays.stream(c.split(","))
                                .map(p -> p.split("="))
                                .collect(Collectors.toMap(p -> p[0], p -> p[1]));

                        String name = params.get("name");
                        String protocol = params.get("protocol");
                        params.remove("name");
                        params.remove("protocol");

                        GuacamoleConfiguration config = new GuacamoleConfiguration();
                        config.setProtocol(protocol);
                        config.setParameters(params);

                        // Store connection using cn for both identifier and name
                        Connection connection = new SimpleConnection(name, name, config, true);
                        connection.setParentIdentifier(OpenIDAuthenticationProvider.ROOT_CONNECTION_GROUP);

                        return connection;
                    })
                    .collect(Collectors.toMap(c -> c.getIdentifier(), c -> c));

            return map;
        } catch (MalformedClaimException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public User self() {
        return self;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Directory<User> getUserDirectory() throws GuacamoleException {
        return userDirectory;
    }

    @Override
    public Directory<UserGroup> getUserGroupDirectory() throws GuacamoleException {
        return userGroupDirectory;
    }

    @Override
    public Directory<Connection> getConnectionDirectory()
            throws GuacamoleException {
        return connectionDirectory;
    }

    @Override
    public ConnectionGroup getRootConnectionGroup() throws GuacamoleException {
        return rootGroup;
    }

}
