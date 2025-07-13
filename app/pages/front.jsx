import React from 'react'


const front = () => {
  return (
    

        <div className=''>
             <nav>
                <ul>
                    <li className=" flex justify-between mx-[90px] p-4">
                        <img className='w-[40px] h-40px] rounded-full' src="./pages/B.jpg" alt="img" />
                        <a class='rounded-sm transition delay-150 duration-300 ease-in-out hover:-translate-y-1 hover:scale-110 hover:bg-indigo-500 h-7 w-12' href="/">Home</a>
                        <a class='rounded-sm transition delay-150 duration-300 ease-in-out hover:-translate-y-1 hover:scale-110 hover:bg-indigo-500 h-7 w-12' href="/about">About</a>
                        <a class='rounded-sm transition delay-150 duration-300 ease-in-out hover:-translate-y-1 hover:scale-110 hover:bg-indigo-500 h-7 w-15' href="/contact">Contact</a>
                        <a class='rounded-sm transition delay-150 duration-300 ease-in-out hover:-translate-y-1 hover:scale-110 hover:bg-indigo-500 h-7 w-15' href="/services">Services</a>
                    </li>
                </ul>
             </nav>
        </div>

  )
}

export default front