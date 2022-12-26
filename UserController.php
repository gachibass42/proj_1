<?php

declare(strict_types=1);

namespace App\Controller\Api\V1;

use App\Controller\JsonResponseTrait;
use App\Service\User\Authentication;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Exception\MessageDecodingFailedException;
use Symfony\Component\Messenger\MessageBus;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Middleware\MiddlewareInterface;
use Symfony\Component\Messenger\Middleware\StackInterface;
use Symfony\Component\Messenger\Stamp\ReceivedStamp;
use Symfony\Component\Messenger\Transport\Receiver\ReceiverInterface;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

class UserController extends AbstractController
{
    use JsonResponseTrait;

    #[Route('/user/register', name: 'api_v1_user_register', methods: ['GET'])]
    public function register(Authentication $authentication, NormalizerInterface $normalizer): JsonResponse
    {
        $user = $authentication->register();

        return $this->successResponse([
            $normalizer->normalize($user, 'json'),
        ]);
    }

    #[Route('/user/login', name: 'api_v1_user_login', methods: ['GET'])]
    public function login(Request $request, Authentication $authentication): JsonResponse
    {
        $data = $authentication->login(
            $request->get('username'),
            $request->get('password')
        );

        if ($data === null) {
            return $this->errorResponse('User not found', [],Response::HTTP_NOT_FOUND);
        }

        return $this->successResponse([$data]);
    }

    #[Route('/user/jwt', name: 'api_v1_user_jwt', methods: ['GET'])]
    public function userJwt(Authentication $authentication, Request $request): JsonResponse
    {
        return $authentication ->getJwt($request->get('id'));
    }

}



