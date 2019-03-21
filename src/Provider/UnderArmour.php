<?php
namespace Clyer\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class UnderArmour extends AbstractProvider
{
    const API_VERSION = '/v7.1';
    const DOMAIN = 'https://www.mapmyfitness.com';

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return self::DOMAIN.self::API_VERSION.'/oauth2/authorize/';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param  array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return self::DOMAIN.self::API_VERSION.'/oauth2/access_token/';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param  AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return self::DOMAIN.self::API_VERSION.'/user/self/';
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [ ];
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string      $data     Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        $statusCode = $response->getStatusCode();
        if ($statusCode < 200 || $statusCode > 202) {
            throw new IdentityProviderException(
                'authorize failed',
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array       $response
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new UnderArmourResourceOwner($response);
    }
}
