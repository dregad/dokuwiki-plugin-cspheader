<?php
/**
 * DokuWiki Content Security Policy (CSP) plugin
 *
 * Configure via config manager
 *
 * host-expr examples: http://*.foo.com, mail.foo.com:443, https://store.foo.com
 * Besides FQDNs there are some keywords which are allowed 'self', 'none' or data:-URIs
 * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Matthias Schulte <post@lupo49.de>
 * @link       https://www.dokuwiki.org/plugin:cspheader
 */
class action_plugin_cspheader extends DokuWiki_Action_Plugin
{
    /**
     * CSP HTTP Header
     */
    const CSP_HEADER = 'Content-Security-Policy:';

    /**
     * @var array CSP directives names
     * @link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#directives
     */
    const DIRECTIVES = [
        'base-uri',
        //'block-all-mixed-content', // this is a yes/no field and should be handled separately
        'child-src',
        'connect-src',
        'default-src',
        'font-src',
        'form-action',
        'frame-ancestors',
        'frame-src',
        'img-src',
        'manifest-src',
        'media-src',
        'navigate-to',
        'object-src',
        'plugin-types',
        'prefetch-src',
        //'referrer', // deprecated
        //'report-to', // this one isn't widely supported and expects a more complicated setup, skip for now
        'report-uri',
        //'require-sri-for', // obsolete
        'sandbox',
        'script-src',
        'script-src-attr',
        'script-src-elem',
        'style-src',
        'style-src-attr',
        'style-src-elem',
        'trusted-types',
        //'upgrade-insecure-requests', // this is a yes/no field and should be handled separately
        'worker-src',
    ];

    public function register(Doku_Event_Handler $controller)
    {
        $controller->register_hook('ACTION_HEADERS_SEND', 'BEFORE', $this, 'handleHeadersSend');
    }

    /**
     * Handler for the ACTION_HEADERS_SEND event
     *
     * @param Doku_Event $event
     * @param $params
     *
     * @noinspection PhpUnused, PhpUnusedParameterInspection
     */
    public function handleHeadersSend(Doku_Event $event, $params)
    {
        $policies = [];
        foreach (self::DIRECTIVES as $directive) {
            $option = str_replace('-', '', $directive) . 'Value';
            $values = $this->getConf($option);
            $values = explode("\n", $values);
            $values = array_map('trim', $values);
            $values = array_unique($values);
            $values = array_filter($values);
            if (!count($values)) continue;

            $policies[$directive] = join(' ', $values);
        }

        $cspheader = self::CSP_HEADER;
        foreach ($policies as $directive => $value) {
            $cspheader .= " $directive $value;";
        }

        array_push($event->data, $cspheader);
    }
}
