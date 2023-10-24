<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// https://developers.kakao.com/

class Kakao extends OAuth2
{

    /**
     * @var array
     */
    protected array $user = [];

    /**
     * @var array
     */
    protected array $tokens = [];

    protected array $scopes = [
        "email",
        "phone"
    ];


    /**
     * @return string
     */
    public function getName(): string
    {
        return 'kakao';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return 'https://kauth.kakao.com/oauth/authorize?' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            // 'scope' => \implode(' ', $this->getScopes()),
            'state' => \json_encode($this->state),
            'response_type' => 'code'
        ]);
    }

    /**
     * @param string $code
     *
     * @return array
     */
    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $this->tokens = \json_decode($this->request(
                'POST',
                'https://kauth.kakao.com/oauth/token' ,[
                    'Content-type: application/x-www-form-urlencoded;charset=utf-8',
                ],
                \http_build_query([
                    'code' => $code,
                    'client_id' => $this->appID,
                    'client_secret' => $this->appSecret,
                    'redirect_uri' => $this->callback,
                    'scope' => null,
                    'grant_type' => 'authorization_code'
                ])
                
            ), true);
        }

        return $this->tokens;
    }

    /**
     * @param string $refreshToken
     *
     * @return array
     */
    public function refreshTokens(string $refreshToken): array
    {
        $this->tokens = \json_decode($this->request(
            'POST',
            'https://kauth.kakao.com/oauth/token?' . \http_build_query([
                'refresh_token' => $refreshToken,
                'client_id' => $this->appID,
                'client_secret' => $this->appSecret,
                'grant_type' => 'refresh_token'
            ]),[
                'Content-type: application/x-www-form-urlencoded;charset=utf-8',
            ]
        ), true);

        if (empty($this->tokens['refresh_token'])) {
            $this->tokens['refresh_token'] = $refreshToken;
        }

        return $this->tokens;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['id'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        if($user['kakao_account']['email']) {
            return $user['kakao_account']['email'];
        }else {
            return $user['id'].'@apptest.com';
        }
        
        
    }


    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);
        $email = $user['kakao_account']['email'] ? $user['kakao_account']['email'] : $user['id'].'@apptest.com';
        if ($email ?? false) {
            return true;
        }

        return false;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['kakao_account']['name'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $this->user = \json_decode($this->request('GET', 'https://kapi.kakao.com/v2/user/me', ['Authorization: Bearer ' . $accessToken, 'Content-type: application/x-www-form-urlencoded;charset=utf-8']), true);
        }

        return $this->user;

    }
}
