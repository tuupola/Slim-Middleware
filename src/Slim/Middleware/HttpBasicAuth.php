<?php
/**
 * Slim - a micro PHP 5 framework
 *
 * @author      Josh Lockhart <info@slimframework.com>
 * @copyright   2011 Josh Lockhart
 * @link        http://www.slimframework.com
 * @license     http://www.slimframework.com/license
 * @version     2.3.0
 * @package     Slim
 *
 * MIT LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Slim\Middleware;

/**
 * HTTP Basic Authentication
 *
 * Provides HTTP Basic Authentication on given routes
 *
 * @package    Slim
 * @author     Mika Tuupola <tuupola@appelsiini.net>
 */
class HttpBasicAuth extends \Slim\Middleware
{

    public function __construct($users, $path = '/', $realm = 'Protected')
    {
        $this->users = $users;
        $this->path = $path;
        $this->realm = $realm;
    }

    public function call()
    {
        $request = $this->app->request;

        /* If path matches what is given on initialization. */
        if (false !== strpos($request->getPath(), $this->path)) {
            $user = $request->headers('PHP_AUTH_USER');
            $pass = $request->headers('PHP_AUTH_PW');

            /* Check if user and passwords matches. */
            if (isset($this->users[$user]) && $this->users[$user] === $pass) {
                $this->next->call();
            } else {
                $this->app->response->status(401);
                $this->app->response->header('WWW-Authenticate', sprintf('Basic realm="%s"', $this->realm));
                return;
            }
        }
        $this->next->call();
    }
}
