<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class SecurityController extends AbstractController
{
    /**
     * @Route("/register", name="register")
     */
    public function register(Request $request, UserPasswordEncoderInterface $encoder, UserRepository $userRepository)
    {

        // token length, 32 is recommended, as the user will not interact with this, only the frontend
        $tokenLength = 8;

        $user = new User();


        //checks if a request is been made

        if (!$request){
            $data = [
                'message' => 'no request',
            ];
            return new JsonResponse($data, Response::HTTP_NO_CONTENT);
        }

        //assigns the values to the user

        $user->setUsername($request->headers->get('username'));
        $plainTextPassword = $request->headers->get('password');
        $user->setPassword($encoder->encodePassword($user, $plainTextPassword));
        $user->setApiToken(bin2hex(openssl_random_pseudo_bytes($tokenLength)));


        // checks for a valid state in the user, if not an error is returned
        // an unstable object might be an already existing api key, or username

        while ( $userRepository->findBy(array('apiToken' => $user->getApiToken())) ){
            $user->setApiToken(bin2hex(openssl_random_pseudo_bytes($tokenLength)));
        }
        if ( $userRepository->findBy(array('username' => $user->getUsername())) ){
            $data = [
                'message' => 'username already taken',
            ];
            return new JsonResponse($data, Response::HTTP_CONFLICT);
        }

        // TODO: check if password is weak


        // adds the user to the db

        $userRepository->add($user);


        // Builds the response and sends it

        $data = [
            'username' => $user->getUsername(),
            'X-AUTH-TOKEN' => $user->getApiToken(),
            'password crypted' => $user->getPassword(),
        ];

        return new JsonResponse($data, Response::HTTP_CREATED);


    }





    /**
     * @Route("/login", name="login")
     */
    public function login(Request $request, UserPasswordEncoderInterface $encoder, UserRepository $userRepository)
    {
        $password = $request->headers->get('password');
        $username = $request->headers->get('username');

        $user = $userRepository->findOneBy(array('username' => $username));


        if ( !$user or !$encoder->isPasswordValid($user, $password) ){
            $data = [
                'message' => 'username or password not valid',
            ];
            return new JsonResponse($data, Response::HTTP_FORBIDDEN);
        }

        $data = [
            'username' => $user->getUsername(),
            'X-AUTH-TOKEN' => $user->getApiToken(),
        ];

        return new JsonResponse($data, Response::HTTP_OK);
    }
}
