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
     * returns the token length, 32 is recommended, as the user will not interact with this, only the frontend
     */
    private function getTokenLenght(){
        return 8;
    }





    /**
     * @Route("/api/register", name="register")
     *
     * Adds the user to the database if some conditions are meet
     *      the username is not taken
     *      the api key is unique
     *
     * Then returns the username and token of the newly registered user
     */
    public function register(Request $request, UserPasswordEncoderInterface $encoder, UserRepository $userRepository)
    {
        //checks if a request is been made

        if ( !$request ){
            $data = [
                'message' => 'no request',
            ];
            return new JsonResponse($data, Response::HTTP_NO_CONTENT);
        }

        $user = new User();


        //assigns the correct values to the user (from the request)

        $user->setUsername($request->headers->get('username'));
        $plainTextPassword = $request->headers->get('password');
        $user->setPassword($encoder->encodePassword($user, $plainTextPassword));
        $user->setApiToken(bin2hex(openssl_random_pseudo_bytes($this->getTokenLenght())));


        // checks for a valid state in the user, if not an error is returned
        // an unstable object might be an already existing api key, or username

        // checks for unique token
        while ( $userRepository->findBy(array('apiToken' => $user->getApiToken())) ){
            $user->setApiToken(bin2hex(openssl_random_pseudo_bytes($this->getTokenLenght())));
        }

        // checks for unique username
        if ( $userRepository->findBy(array('username' => $user->getUsername())) ){
            // if the username is already in the database, respond with a conflict
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
        ];

        return new JsonResponse($data, Response::HTTP_CREATED);


    }





    /**
     * @Route("/api/login", name="login")
     */
    public function login(Request $request, UserPasswordEncoderInterface $encoder, UserRepository $userRepository)
    {
        $password = $request->headers->get('password');
        $username = $request->headers->get('username');

        $user = $userRepository->findOneBy(array('apiToken' => $username));


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






    /**
     * @Route("/api/modify", name="modify")
     */
    public function modify(Request $request, UserPasswordEncoderInterface $encoder, UserRepository $userRepository)
    {
        $plainTextPassword = $request->headers->get('password');
        $token = $request->headers->get('X-AUTH-TOKEN');

        $user = $userRepository->findOneBy(array('apiToken' => $token));

        if ( !$user ){
            $data = [
                'message' => 'invalid token',
            ];
            return new JsonResponse($data, Response::HTTP_FORBIDDEN);
        }

        if ( $plainTextPassword ){
            $user->setPassword($encoder->encodePassword($user, $plainTextPassword));
        }


        $user->setApiToken(bin2hex(openssl_random_pseudo_bytes($this->getTokenLenght())));


        // checks for a valid state in the user, if not an error is returned
        // an unstable object might be an already existing api key, or username

        while ( $userRepository->findBy(array('apiToken' => $user->getApiToken())) ){
            $user->setApiToken(bin2hex(openssl_random_pseudo_bytes($this->getTokenLenght())));
        }

        $userRepository->modify($user);

        $data = [
            'username' => $user->getUsername(),
            'X-AUTH-TOKEN' => $user->getApiToken(),
        ];

        return new JsonResponse($data, Response::HTTP_OK);
    }
}
