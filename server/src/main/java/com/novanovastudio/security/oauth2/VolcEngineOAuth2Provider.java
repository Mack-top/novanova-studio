package com.novanovastudio.security.oauth2;

import com.novanovastudio.config.NovanovaProperties;
import java.net.URI;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 火山引擎（Volcengine）OAuth2.0 单点登录渠道实现。
 *
 * <p>火山 SSO 为企业级能力：授权端点由 Spring Security 配置注入，令牌端点与
 * 用户信息端点由企业管理员按火山下发的地址配置（参见火山官方文档
 * 「OAuth2.0 单点登录的接口标准」：access_token 返回 {access_token, token_type,
 * refresh_token, expire_in}，user_info 返回 {user: {name}}）。
 *
 * <p>火山标准响应可能不含 OIDC 标准声明（sub/email），这里做了兼容：
 * 标识优先取 sub，其次 user_id/name；邮箱缺失时生成占位邮箱以保证身份绑定表
 * （user_identity_bindings）唯一约束可用。
 */
@Component
@RequiredArgsConstructor
public class VolcEngineOAuth2Provider implements ThirdPartyOAuth2Provider {

    /** 渠道唯一标识 */
    public static final String PROVIDER_ID = "volc";

    /** OAuth2回调路径 */
    private static final String CALLBACK_PATH = "/api/v1/auth/oauth/callback/volc";

    /** 占位邮箱域名（火山 SSO 不保证返回邮箱时使用） */
    private static final String PLACEHOLDER_EMAIL_DOMAIN = "sso.volc-placeholder.invalid";

    /** 第三方用户标识最大长度 */
    private static final int MAX_PROVIDER_USER_ID_LENGTH = 128;

    /** 邮箱最大长度 */
    private static final int MAX_EMAIL_LENGTH = 100;

    /** 本地昵称最大长度 */
    private static final int MAX_NICKNAME_LENGTH = 50;

    /** 头像地址最大长度 */
    private static final int MAX_AVATAR_LENGTH = 255;

    /** 服务配置 */
    private final NovanovaProperties properties;

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String displayName() {
        return "火山引擎";
    }

    @Override
    public boolean enabled() {
        return properties.getOauth2().getVolc().isEnabled();
    }

    @Override
    public ClientRegistration clientRegistration() {
        NovanovaProperties.OAuth2.Volc configuration = properties.getOauth2().getVolc();
        requireConfiguration(configuration.getClientId(), "OAUTH2_VOLC_CLIENT_ID");
        requireConfiguration(configuration.getClientSecret(), "OAUTH2_VOLC_CLIENT_SECRET");
        requireConfiguration(configuration.getRedirectUri(), "OAUTH2_VOLC_REDIRECT_URI");
        requireConfiguration(configuration.getTokenUri(), "OAUTH2_VOLC_TOKEN_URI");
        requireConfiguration(configuration.getUserInfoUri(), "OAUTH2_VOLC_USER_INFO_URI");
        String redirectUri = validatedRedirectUri(configuration.getRedirectUri());
        validatedEndpointUri(configuration.getTokenUri(), "OAUTH2_VOLC_TOKEN_URI");
        validatedEndpointUri(configuration.getUserInfoUri(), "OAUTH2_VOLC_USER_INFO_URI");
        // 火山企业 SSO 不一定下发 id_token，userInfoUri 是身份来源；
        // userNameAttributeName 指向 sub，缺失时由 resolveIdentity 兜底取 user_id/name。
        return ClientRegistration.withRegistrationId(PROVIDER_ID)
                .clientId(configuration.getClientId().trim())
                .clientSecret(configuration.getClientSecret().trim())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope("openid")
                .authorizationUri(resolveAuthorizationUri(configuration))
                .tokenUri(configuration.getTokenUri().trim())
                .userInfoUri(configuration.getUserInfoUri().trim())
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientName(displayName())
                .build();
    }

    @Override
    public ThirdPartyUserIdentity resolveIdentity(OidcUser user) {
        String providerUserId = firstNonEmpty(
                claim(user, IdTokenClaimNames.SUB),
                claim(user, "user_id"),
                claim(user, "userId"),
                claim(user, "name"));
        if (!StringUtils.hasText(providerUserId)) {
            throw new OAuth2LoginException("providerIdentityUnavailable", "火山账号未返回可用的用户标识");
        }
        providerUserId = providerUserId.toLowerCase(Locale.ROOT);
        requireMaximumLength(providerUserId, MAX_PROVIDER_USER_ID_LENGTH, "火山用户标识长度超过系统限制");

        String email = claim(user, "email");
        if (StringUtils.hasText(email)) {
            email = email.toLowerCase(Locale.ROOT);
            if (email.length() > MAX_EMAIL_LENGTH || !email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
                throw new OAuth2LoginException("emailUnavailable", "火山账号返回的邮箱格式不正确");
            }
        } else {
            // 火山企业 SSO 的 user_info 标准响应只有 {user:{name}}，可能没有邮箱；
            // 用稳定占位邮箱保证身份绑定表唯一约束可写，不参与真实邮件收发。
            email = ("volc-" + providerUserId + "@" + PLACEHOLDER_EMAIL_DOMAIN).toLowerCase(Locale.ROOT);
        }

        String nickname = firstNonEmpty(
                claim(user, "name"),
                claim(user, "preferred_username"),
                claim(user, "nickname"),
                claim(user, "username"),
                emailName(email));
        requireMaximumLength(nickname, MAX_NICKNAME_LENGTH, "火山昵称长度超过系统限制");
        String avatar = firstNonEmpty(claim(user, "avatar"), claim(user, "picture"));
        requireMaximumLength(avatar, MAX_AVATAR_LENGTH, "火山头像地址长度超过系统限制");
        return new ThirdPartyUserIdentity(providerId(), providerUserId, email, nickname, avatar);
    }

    /**
     * 解析授权端点：优先取 Spring Security OAuth2 Client 标准的
     * OAUTH2_VOLC_AUTHORIZATION_URI 环境变量（由部署方注入到系统属性/环境），
     * 未配置时退回令牌端点同域的 /oauth/authorize。
     */
    private String resolveAuthorizationUri(NovanovaProperties.OAuth2.Volc configuration) {
        String explicit = System.getenv("OAUTH2_VOLC_AUTHORIZATION_URI");
        if (StringUtils.hasText(explicit)) {
            return explicit.trim();
        }
        try {
            URI token = URI.create(configuration.getTokenUri().trim());
            String scheme = token.getScheme() == null ? "https" : token.getScheme();
            String authority = token.getRawAuthority() == null ? "" : token.getRawAuthority();
            return scheme + "://" + authority + "/oauth/authorize";
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("OAUTH2_VOLC_TOKEN_URI不是合法地址，无法推导授权端点", exception);
        }
    }

    private void requireConfiguration(String value, String environmentName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalStateException("已启用火山引擎SSO登录，但未配置" + environmentName);
        }
    }

    private String validatedRedirectUri(String value) {
        URI redirectUri;
        try {
            redirectUri = URI.create(value.trim());
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("OAUTH2_VOLC_REDIRECT_URI不是合法地址", exception);
        }
        boolean supportedScheme = "https".equalsIgnoreCase(redirectUri.getScheme()) || "http".equalsIgnoreCase(redirectUri.getScheme());
        if (!supportedScheme || !StringUtils.hasText(redirectUri.getHost()) || !CALLBACK_PATH.equals(redirectUri.getPath())
                || redirectUri.getQuery() != null || redirectUri.getFragment() != null) {
            throw new IllegalStateException("OAUTH2_VOLC_REDIRECT_URI必须是绝对HTTP地址且路径为" + CALLBACK_PATH);
        }
        return redirectUri.toString();
    }

    private void validatedEndpointUri(String value, String environmentName) {
        try {
            URI endpoint = URI.create(value.trim());
            boolean supportedScheme = "https".equalsIgnoreCase(endpoint.getScheme()) || "http".equalsIgnoreCase(endpoint.getScheme());
            if (!supportedScheme || !StringUtils.hasText(endpoint.getHost())) {
                throw new IllegalStateException(environmentName + "必须是绝对HTTP(S)地址");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(environmentName + "不是合法地址", exception);
        }
    }

    private String claim(OidcUser user, String claimName) {
        Object value = user.getClaims().get(claimName);
        if (value instanceof String stringValue) {
            return stringValue.trim();
        }
        if (value instanceof Number numberValue) {
            return String.valueOf(numberValue);
        }
        return "";
    }

    private void requireMaximumLength(String value, int maximumLength, String errorMessage) {
        if (value != null && value.length() > maximumLength) {
            throw new OAuth2LoginException("providerProfileInvalid", errorMessage);
        }
    }

    private String emailName(String email) {
        int separatorIndex = email.indexOf('@');
        return separatorIndex > 0 ? email.substring(0, separatorIndex) : email;
    }

    private String firstNonEmpty(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }
}
