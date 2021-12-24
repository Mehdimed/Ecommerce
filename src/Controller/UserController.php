<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\ChangePasswordType;
use App\Form\InscriptionType;
use App\Security\LoginFormAuthenticator;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\File\Exception\FileException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;

class UserController extends AbstractController
{
    /**
     * @Route("/inscription", name="inscription")
     */
    public function insription(Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $encoder,UserAuthenticatorInterface $authenticator, LoginFormAuthenticator $formAuthenticator): Response
    {
        $user = new User;
    
        $form = $this->createForm(InscriptionType::class, $user);

        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $user = $form->getData();
            $user->setRoles(['ROLE_USER']);

            $password = $encoder->hashPassword($user, $user->getPassword());
            $user->setPassword($password);

            $em->persist($user);
            $em->flush();

            return $authenticator->authenticateUser(
                $user, 
                $formAuthenticator, 
                $request);
        }

        return $this->render('user/inscription.html.twig', [
            'form' => $form->createView()
        ]);
    }

    /**
     * @Route("/profil", name="profil")
     */
    public function profil()
    {
        $user = $this->getUser();

        if(!$user){
            throw new \Exception('Vous devez être connecté');
        }

        return $this->render('user/profil.html.twig');

    }

    /**
     * @Route("/profil/changePassword", name="changePassword")
     */
    public function changePassword(Request $request,EntityManagerInterface $em,UserPasswordHasherInterface $encoder){

        $user = $this->getUser();

        if(!$user){
            throw new \Exception('Vous devez être connecté');
        }
    
        $form = $this->createForm(ChangePasswordType::class);

        $form->handleRequest($request);
        if($form->isSubmitted() && $form->isValid()){
            $data = $form->getData();
            if($encoder->isPasswordValid($user, $data['oldPassword'])){
                $newPassword = $encoder->hashPassword($user, $data['newPassword']);
                $user->setPassword($newPassword);
                $em->flush();

                return $this->redirectToRoute('home');
            }
            
        }
            

        return $this->render('user/changePassword.html.twig', [
            'form' => $form->createView()
        ]);
    }
}
