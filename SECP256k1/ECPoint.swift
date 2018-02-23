//
//  ECPoint.swift
//  Created by Boris Polania on 2/19/18.
//  Copyright © 2018 Boris Polania. All rights reserved.
//

import UIKit

class ECPoint: NSObject {
    
    let x   : BDouble
    let y   : BDouble
    let inf : Bool
    
    init(x: BDouble?, y: BDouble?) {
        self.x = x!
        self.y = y!
        self.inf = false
    }
    
    func getNAFPoints(windowSize: Int) -> [String: Any] {
        var points = [ECPoint]()
        points.append(self)
        let double = self.double()
        for i in 1...points.count {
            points[i] = points[i - 1].add(point: double)
        }
        return ["windowSize": windowSize, "points": points]
        
    }
    
    func double() -> ECPoint {
        if self.inf {return self}
        
        if self.y * 2 == BDouble(0) {
            return ECPoint(x:nil,y:nil)
        }
        let s  = (BDouble(3) * (self.x * self.x)) / (Double(2) * self.y)
        let nx = (s * s) - (Double(2) * self.x)
        let ny = s * (self.x - nx) - self.y
        return ECPoint(x: nx, y: ny)
    }
    
    func add(point: ECPoint) -> ECPoint {
        // O + P = P
        if self.inf {return point}
        // P + O = P
        if point.inf {return self}
        
        if self.x == point.x {
            // P + P = 2P
            if self.x == point.x {
                if self.y == point.y {return self.double()}
            }
            // P + (-P) = O
            return ECPoint(x:nil,y:nil)
        }
        // s = (y - yp) / (x - xp)
        // nx = s^2 - x - xp
        // ny = s * (x - nx) - y
        let s  = (self.y - point.y) / (self.x - point.x)
        let nx = (s * s) - self.x - point.x
        let ny = s * (self.x - nx) - self.y
        return ECPoint(x: nx, y: ny)
    }
    
    func multiplication(number: BDouble) {
        // Algorithm 3.36 Window NAF method for point multiplication
        var nafPoints = self.getNAFPoints(windowSize: 4)
        var points    = nafPoints["points"] as! [ECPoint]
        // Get Non-Adjacent Form
        
        var i = UInt(8)
        
    }
    
    
    


}
