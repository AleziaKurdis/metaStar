<?php
declare(strict_types=1);

namespace OvertePHP;

final class Router
{
    private array $routes = [];

    public function add(string $method, string $pattern, callable $handler): void
    {
        $quoted = preg_quote($pattern, '#');
        $regex = preg_replace_callback('/\\\\\{([a-zA-Z][a-zA-Z0-9_]*)\\\\\}/', static fn(array $m): string => '(?P<' . $m[1] . '>[^/]+)', $quoted);
        $this->routes[] = [strtoupper($method), '#^' . $regex . '/?$#', $handler];
    }

    public function dispatch(string $method, string $path, JsonStore $store, Auth $auth, array $config): void
    {
        foreach ($this->routes as [$routeMethod, $regex, $handler]) {
            if ($routeMethod !== strtoupper($method) && $routeMethod !== 'ANY') {
                continue;
            }
            if (preg_match($regex, $path, $matches)) {
                $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);
                $handler($params, $store, $auth, $config);
                return;
            }
        }
        Http::failure('Route not found', 404);
    }
}
