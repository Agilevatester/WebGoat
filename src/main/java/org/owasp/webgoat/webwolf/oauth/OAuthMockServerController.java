/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.webwolf.oauth;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Lightweight mock OAuth 2.0 Authorization Server running inside WebWolf.
 *
 * <p>This is a simplified, intentionally non-production OAuth server designed for use in the
 * WebGoat "MFA OAuth Account Linking Pitfall" lesson (Technique 9). It provides the three
 * endpoints required to simulate a complete Authorization Code flow:
 *
 * <ul>
 *   <li>{@code GET /WebWolf/oauth2/authorize} — consent page; user enters their WebWolf identity
 *       and approves access. Generates an authorization code and redirects to the client.
 *   <li>{@code POST /WebWolf/oauth2/token} — token endpoint; exchanges the authorization code
 *       for an opaque access token.
 *   <li>{@code GET /WebWolf/oauth2/userinfo} — resource endpoint; returns the identity of the
 *       user who authorized the code, identified by the Bearer token.
 * </ul>
 *
 * <p>Codes and tokens are stored in static in-memory maps. In a real OAuth server these would be
 * persisted, signed (JWTs), and have short expiry. Here they are intentionally simple so students
 * can focus on the account-linking vulnerability in WebGoat rather than OAuth internals.
 *
 * <p>All three endpoints are added to WebWolf's security permit list so they can be reached
 * without a WebWolf login session (the user identity is supplied via the consent form instead).
 */
@Controller
public class OAuthMockServerController {

  // In-memory stores — acceptable for a single-JVM lesson tool
  private static final ConcurrentHashMap<String, String> AUTH_CODES = new ConcurrentHashMap<>();
  private static final ConcurrentHashMap<String, String> ACCESS_TOKENS = new ConcurrentHashMap<>();

  /**
   * Authorization endpoint — shows a consent page.
   *
   * <p>The user enters their WebWolf username (simulating "you are already logged into WebWolfSSO")
   * and clicks Approve. The server generates an authorization code and redirects to
   * {@code redirect_uri?code=<code>&state=<state>}.
   *
   * <p>A production OAuth server would authenticate the user via a secure login flow instead of
   * accepting a username from a form field.
   */
  @GetMapping("/oauth2/authorize")
  public String authorize(
      @RequestParam(required = false) String client_id,
      @RequestParam String redirect_uri,
      @RequestParam(required = false) String state,
      @RequestParam(required = false, defaultValue = "code") String response_type,
      Model model) {

    model.addAttribute("client_id", client_id);
    model.addAttribute("redirect_uri", redirect_uri);
    model.addAttribute("state", state != null ? state : "");
    return "oauth-consent"; // Thymeleaf template
  }

  /**
   * Consent form POST — approves access and issues an authorization code.
   *
   * <p>Called when the user submits the consent form. The {@code webwolfUser} field represents the
   * WebWolf identity granting access (in a real server this comes from the authenticated session).
   */
  @PostMapping("/oauth2/approve")
  public String approve(
      @RequestParam String webwolfUser,
      @RequestParam String redirect_uri,
      @RequestParam(required = false) String state) {

    String code = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    AUTH_CODES.put(code, webwolfUser.trim());

    String location = redirect_uri + "?code=" + code + (state != null ? "&state=" + state : "");
    return "redirect:" + location;
  }

  /**
   * Token endpoint — exchanges an authorization code for an access token.
   *
   * <p>Accepts {@code application/x-www-form-urlencoded} as per RFC 6749. The client secret
   * ({@code webgoat-secret}) is accepted for any value here since this is a lesson tool.
   */
  @PostMapping(path = "/oauth2/token", produces = "application/json")
  @ResponseBody
  public ResponseEntity<Map<String, Object>> token(
      @RequestParam String grant_type,
      @RequestParam String code,
      @RequestParam(required = false) String client_id,
      @RequestParam(required = false) String client_secret,
      @RequestParam(required = false) String redirect_uri) {

    if (!"authorization_code".equals(grant_type)) {
      return ResponseEntity.badRequest()
          .body(Map.of("error", "unsupported_grant_type"));
    }

    String username = AUTH_CODES.remove(code);
    if (username == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("error", "invalid_grant", "error_description", "Code not found or expired"));
    }

    String token = UUID.randomUUID().toString();
    ACCESS_TOKENS.put(token, username);

    return ResponseEntity.ok(
        Map.of(
            "access_token", token,
            "token_type", "Bearer",
            "expires_in", 3600,
            "scope", "read"));
  }

  /**
   * UserInfo endpoint — returns the identity of the token holder.
   *
   * <p>Expects {@code Authorization: Bearer <token>} header. Returns a minimal JSON user profile
   * with {@code sub} (subject), {@code name}, and {@code email} fields.
   */
  @GetMapping(path = "/oauth2/userinfo", produces = "application/json")
  @ResponseBody
  public ResponseEntity<Map<String, String>> userinfo(
      @RequestHeader(value = "Authorization", required = false) String authHeader,
      HttpServletRequest request) {

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("error", "invalid_token", "error_description", "Bearer token required"));
    }

    String token = authHeader.substring(7).trim();
    String username = ACCESS_TOKENS.get(token);

    if (username == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("error", "invalid_token", "error_description", "Token not found or expired"));
    }

    return ResponseEntity.ok(
        Map.of(
            "sub", username,
            "name", username,
            "email", username + "@webwolf.test",
            "provider", "WebWolfSSO"));
  }
}
