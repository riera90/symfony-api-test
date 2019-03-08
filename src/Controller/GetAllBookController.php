<?php

namespace App\Controller;

use App\Entity\Book;
use App\Repository\BookRepository;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;


class GetAllBookController extends Controller
{


    public function __construct()
    {
    }

    public function __invoke(Book $data): Book
    {
        $user = $token->getUser();
        if ($data->getOwner()->getApiToken() === $user->getApiToken() ){
            $data->setTitle("asdasdasdasdasdadsasdasdasd");
        }
        return $data;
    }
}
